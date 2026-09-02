// Part two of papers/quo-truth.md: what a being receives, played as Alice, Bob
// and the clinic. Written from the paper alone. The beings below know which of
// their references are Quo and nothing about roads or hosts.
package warden_test

import (
	"context"
	"fmt"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/notation"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

const dogText = `Dog
  name() text
  logWalk(minutes int) bool
  vaccinated() bool?
  invite() invitation
`

var intList = notation.List(notation.Type{Kind: notation.KindInt})

// Dog is Alice's. It reaches the clinic through a private label, and it has
// never heard of a road, a host or a key.
type Dog struct {
	warden.Attach
	dogName string
	walks   []int64
	leashes []int64
}

func (d *Dog) Name() string { return d.dogName }

func (d *Dog) LogWalk(minutes int64) bool {
	d.walks = append(d.walks, minutes)
	return true
}

func (d *Dog) Vaccinated(ctx context.Context) any {
	d.leashes = append(d.leashes, warden.Of(ctx).Leash.Received().Hops)
	record := d.Quo().Relation("clinic")
	if record == nil {
		return nil
	}
	v, ok := record.Call(ctx, "vaccinated")
	if !ok {
		return nil
	}
	return v
}

func (d *Dog) Invite() (wire.Invitation, error) { return d.Quo().Grant(nil) }

// Cells and Take are the contract: what of its state moves with it, and how it
// takes that state back.
func (d *Dog) Cells() []byte {
	out := make([]any, 0, len(d.walks))
	for _, w := range d.walks {
		out = append(out, w)
	}
	b, err := wire.Encode(warden.Own, intList, out)
	if err != nil {
		return []byte{}
	}
	return b
}

func (d *Dog) Take(cells []byte) error {
	v, err := wire.Decode(warden.Own, intList, cells)
	if err != nil {
		return err
	}
	d.walks = nil
	for _, one := range v.([]any) {
		d.walks = append(d.walks, one.(int64))
	}
	return nil
}

const recordText = `Record
  vaccinated() bool
`

type Record struct {
	warden.Attach
	callers [][32]byte
	leashes []int64
}

func (r *Record) Vaccinated(ctx context.Context) bool {
	scope := warden.Of(ctx)
	r.callers = append(r.callers, scope.Caller.Voice)
	r.leashes = append(r.leashes, scope.Leash.Received().Hops)
	return true
}

const profileText = `Profile
  name() text
  rate() int
`

type Profile struct{ warden.Attach }

func (p *Profile) Name() string { return "Bob" }
func (p *Profile) Rate() int64  { return 20 }

const walkerText = `Walker
  subscribe(inbox invitation) bool
  walk(minutes int) bool
  secret() text
`

type Walker struct {
	warden.Attach
	listener warden.Handle
}

func (w *Walker) Subscribe(ctx context.Context, inv wire.Invitation) bool {
	// A standing answers a handle per being it names, and an invitation to a
	// subscriber's own callback names one.
	listeners, err := w.Quo().Accept(ctx, inv, "inbox")
	if err != nil || len(listeners) != 1 {
		return false
	}
	w.listener = listeners[0]
	return true
}

func (w *Walker) Walk(ctx context.Context, minutes int64) bool {
	rex := w.Quo().Relation("rex")
	if rex == nil {
		return false
	}
	if _, ok := rex.Call(ctx, "logWalk", minutes); !ok {
		return false
	}
	if w.listener != nil {
		w.listener.Call(ctx, "walked", minutes)
	}
	return true
}

func (w *Walker) Secret() string { return "nobody sees this" }

const inboxText = `Inbox
  walked(minutes int)
`

type Inbox struct {
	warden.Attach
	heard []int64
}

func (i *Inbox) Walked(minutes int64) { i.heard = append(i.heard, minutes) }

type world struct {
	phone, laptop, clinic *warden.Warden
	rex                   *Dog
	inbox                 *Inbox
	walker                *Walker
	profile               *Profile
	record                *Record
}

func village(t *testing.T) *world {
	t.Helper()
	d := warden.NewMemory()
	at := func(hint string) *warden.Warden {
		w := open(t, d, seeds(), nil)
		d.Attach(hint, w)
		w.Publish(hint)
		return w
	}
	one := &world{
		phone:   at("mem://alice"),
		laptop:  at("mem://bob"),
		clinic:  at("mem://clinic"),
		rex:     &Dog{dogName: "Rex"},
		inbox:   &Inbox{},
		walker:  &Walker{},
		profile: &Profile{},
		record:  &Record{},
	}
	hold := func(w *warden.Warden, object any, blueprint string) {
		if _, _, err := w.Hold(object, warden.Holding{Blueprint: blueprint}); err != nil {
			t.Fatal(err)
		}
	}
	hold(one.phone, one.rex, dogText)
	hold(one.phone, one.inbox, inboxText)
	hold(one.laptop, one.walker, walkerText)
	hold(one.laptop, one.profile, profileText)
	hold(one.clinic, one.record, recordText)
	return one
}

func ctx() context.Context { return context.Background() }

// sole is the handle of a standing that names one being, with the accept's own
// answer held to that. A standing naming several answers several, and the
// cases that mean one say so here.
func sole(handles []warden.Handle, err error) (warden.Handle, error) {
	if err != nil {
		return nil, err
	}
	if len(handles) != 1 {
		return nil, fmt.Errorf("the standing answered %d handles", len(handles))
	}
	return handles[0], nil
}

func TestAliceLetsBobWalkRex(t *testing.T) {
	w := village(t)
	inv, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), inv, "rex"); err != nil {
		t.Fatal(err)
	}
	if v, ok := w.walker.Quo().Relation("rex").Call(ctx(), "name"); !ok || v.(string) != "Rex" {
		t.Fatalf("name answered %v %v", v, ok)
	}
	if !w.walker.Walk(ctx(), 30) {
		t.Fatal("the walk was not logged")
	}
	if len(w.rex.walks) != 1 || w.rex.walks[0] != 30 {
		t.Fatalf("Rex was walked %v", w.rex.walks)
	}
}

func TestBobNarrowsWhatAliceSees(t *testing.T) {
	w := village(t)
	inv, err := w.profile.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(w.rex.Quo().Accept(ctx(), inv, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(ctx(), "name"); !ok || v.(string) != "Bob" {
		t.Fatalf("name answered %v %v", v, ok)
	}
	if v, ok := handle.Call(ctx(), "rate"); !ok || v.(int64) != 20 {
		t.Fatalf("rate answered %v %v", v, ok)
	}
	// Alice's estate at Bob's door holds Profile and the public being, nothing
	// of Walker. Its fields do not exist for her.
	if _, ok := handle.Call(ctx(), "secret"); ok {
		t.Fatal("Walker's field answered through Profile's handle")
	}
	if len(w.walker.Quo().Standings()) != 0 {
		t.Fatal("Alice was given a standing at Walker")
	}
}

func TestTheChainSeesRexNotBob(t *testing.T) {
	w := village(t)
	inv, err := w.record.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.rex.Quo().Accept(ctx(), inv, "clinic"); err != nil {
		t.Fatal(err)
	}
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	v, ok := w.walker.Quo().Relation("rex").Call(ctx(), "vaccinated")
	if !ok || v != true {
		t.Fatalf("vaccinated answered %v %v", v, ok)
	}
	// Rex's voice at the clinic is the one the clinic minted for Rex; Bob has
	// no standing there and could not ask directly.
	if len(w.record.callers) != 1 {
		t.Fatalf("the clinic saw %d callers", len(w.record.callers))
	}
	held := w.record.Quo().Standings()
	if len(held) != 1 || held[0] != w.record.callers[0] {
		t.Fatal("the clinic saw a voice it did not mint for Rex")
	}
}

func TestTheLeashShrinksByOneHopAlongTheChain(t *testing.T) {
	w := village(t)
	inv, err := w.record.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.rex.Quo().Accept(ctx(), inv, "clinic"); err != nil {
		t.Fatal(err)
	}
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	// Rex's own leash is read where Rex answers, and the clinic's where the
	// clinic does; the second is one hop shorter than the first, and a being
	// never widens one.
	if _, ok := w.walker.Quo().Relation("rex").Call(ctx(), "vaccinated"); !ok {
		t.Fatal("the chain fell silent")
	}
	if len(w.rex.leashes) != 1 || len(w.record.leashes) != 1 {
		t.Fatalf("the chain recorded %d and %d leashes", len(w.rex.leashes), len(w.record.leashes))
	}
	if w.record.leashes[0] != w.rex.leashes[0]-1 {
		t.Fatalf("Rex was handed %d hops and the clinic %d", w.rex.leashes[0], w.record.leashes[0])
	}
	if w.rex.leashes[0] != warden.DefaultAllowance.Hops {
		t.Fatalf("a walk started here was born with %d hops", w.rex.leashes[0])
	}
}

func TestSubscriptionIsAGrantBackwards(t *testing.T) {
	w := village(t)
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	// Alice hands Bob's Walker an invitation to Inbox, through a field Walker
	// declares. There is no subscribe verb anywhere beneath this.
	granted, err := w.walker.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := sole(w.rex.Quo().Accept(ctx(), granted, "walker"))
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := w.inbox.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := bob.Call(ctx(), "subscribe", inbox); !ok || v != true {
		t.Fatalf("subscribe answered %v %v", v, ok)
	}
	bob.Call(ctx(), "walk", int64(15))
	bob.Call(ctx(), "walk", int64(25))
	if len(w.inbox.heard) != 2 || w.inbox.heard[0] != 15 || w.inbox.heard[1] != 25 {
		t.Fatalf("Inbox heard %v", w.inbox.heard)
	}
	if len(w.rex.walks) != 2 {
		t.Fatalf("Rex was walked %v", w.rex.walks)
	}
}

func TestUnsubscribingNeedsNoVerb(t *testing.T) {
	w := village(t)
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	granted, err := w.walker.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := sole(w.rex.Quo().Accept(ctx(), granted, "walker"))
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := w.inbox.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob.Call(ctx(), "subscribe", inbox)
	bob.Call(ctx(), "walk", int64(10))
	w.inbox.Quo().Release(w.inbox.Quo().Being())
	// The walk is still logged; only the push finds nobody.
	if v, ok := bob.Call(ctx(), "walk", int64(20)); !ok || v != true {
		t.Fatalf("walk answered %v %v", v, ok)
	}
	if len(w.inbox.heard) != 1 {
		t.Fatalf("Inbox heard %v after being released", w.inbox.heard)
	}
	if len(w.rex.walks) != 2 {
		t.Fatalf("Rex was walked %v", w.rex.walks)
	}
}

func TestAliceFiresBob(t *testing.T) {
	w := village(t)
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	handle := w.walker.Quo().Relation("rex")
	if v, ok := handle.Call(ctx(), "logWalk", int64(5)); !ok || v != true {
		t.Fatalf("logWalk answered %v %v", v, ok)
	}
	held := w.rex.Quo().Standings()
	if len(held) != 1 {
		t.Fatalf("Rex holds %d standings", len(held))
	}
	if err := w.rex.Quo().Amend(held[0], nil, [][32]byte{w.rex.Quo().Being()}); err != nil {
		t.Fatal(err)
	}
	if _, ok := handle.Call(ctx(), "logWalk", int64(5)); ok {
		t.Fatal("a fired walker still writes")
	}
	if _, ok := handle.Call(ctx(), "name"); ok {
		t.Fatal("a fired walker still reads")
	}
	if len(w.rex.walks) != 1 {
		t.Fatalf("Rex was walked %v", w.rex.walks)
	}
}

func TestSilenceAfterAWriteIsHonouredAtMostOnce(t *testing.T) {
	w := village(t)
	rex, err := w.rex.Invite()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.walker.Quo().Accept(ctx(), rex, "rex"); err != nil {
		t.Fatal(err)
	}
	handle := w.walker.Quo().Relation("rex")
	// The handle hands back the envelope it sealed, so a caller that met
	// silence resends the same bytes and never a fresh number.
	sealed, err := handle.Seal(ctx(), "logWalk", int64(40))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Send(ctx(), sealed); !ok || v != true {
		t.Fatalf("the sealed write answered %v %v", v, ok)
	}
	if _, ok := handle.Send(ctx(), sealed); ok {
		t.Fatal("the same envelope was honoured twice")
	}
	if len(w.rex.walks) != 1 || w.rex.walks[0] != 40 {
		t.Fatalf("Rex was walked %v", w.rex.walks)
	}
}

func TestASameWardenCallGoesThroughTheHandle(t *testing.T) {
	w := village(t)
	var refused []warden.Silence
	w.phone.Observe(func(s warden.Silence) { refused = append(refused, s) })
	_, handle, err := w.rex.Quo().Hold(&Dog{dogName: "Pup"}, warden.Holding{Blueprint: dogText, Label: "pup"})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(ctx(), "name"); !ok || v.(string) != "Pup" {
		t.Fatalf("name answered %v %v", v, ok)
	}
	if v, ok := w.rex.Quo().Relation("pup").Call(ctx(), "logWalk", int64(3)); !ok || v != true {
		t.Fatalf("logWalk answered %v %v", v, ok)
	}
	// Nothing was judged: the door was never asked and never fell silent.
	if len(refused) != 0 {
		t.Fatalf("the door judged %d messages for a call beside it", len(refused))
	}
}

// A migration carries one being. Rex mints Landing beside itself and a peer
// takes a standing at Landing; when Rex departs, Landing stays where it was
// minted and the standing at it is untouched. No warden records which being
// minted which, and this is why none needs to.
func TestAMigrationCarriesOneBeingAndWhatItMintedStaysBehind(t *testing.T) {
	origin := house(t, "minter")
	peer := house(t, "minter-peer")

	rex := &Dog{dogName: "Rex"}
	rexPk, _, err := origin.Hold(rex, warden.Holding{
		Blueprint: dogText,
		Keys:      warden.Keys{Secret: secret("minter/rex"), HeirSecret: secret("minter/rexHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	held := &Inbox{}
	landingPk, landing, err := rex.Quo().Hold(held, warden.Holding{Blueprint: inboxText})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := origin.GrantAs(landingPk,
		warden.Keys{Secret: secret("minter/voice"), HeirSecret: secret("minter/voiceHeir")},
		origin.Padlock(), []string{"https://minter.example"})
	if err != nil {
		t.Fatal(err)
	}
	peer.Stand(peer.Self(), inv, inv.HeirSecret)

	// Nothing of Landing's is in Rex's cargo: the peers a cargo carries are the
	// ones standing at the being that moves.
	cargo, err := origin.Pack(rexPk, rex.Cells())
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range cargo.Standings {
		for _, at := range one.Beings {
			if at == landingPk {
				t.Fatal("Landing travelled in Rex's cargo")
			}
		}
	}

	before := len(origin.Standings(landingPk))
	departed, err := origin.Depart(rexPk, warden.Departing{
		HeirSecret: secret("minter/rexHeir"),
		Commitment: arithmetic.Commit(peer.Name(), arithmetic.SigningKey(secret("minter/arrived"))),
		Name:       peer.Name(),
		Padlock:    peer.Padlock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if departed.Voice != arithmetic.SigningKey(secret("minter/rexHeir")) {
		t.Fatal("Rex did not depart on its committed heir")
	}

	// Landing stands where it was minted, with the standing at it what it was
	// before the move, and it still answers.
	if _, err := origin.Pack(landingPk, nil); err != nil {
		t.Fatalf("Landing left with its minter: %v", err)
	}
	if now := len(origin.Standings(landingPk)); now != before || now != 1 {
		t.Fatalf("the standing at Landing is %d, was %d", now, before)
	}
	if _, ok := landing.Call(ctx(), "walked", int64(11)); !ok {
		t.Fatal("Landing stopped answering when its minter left")
	}
	if len(held.heard) != 1 || held.heard[0] != 11 {
		t.Fatalf("Landing heard %v", held.heard)
	}
}

// digestOf is a class's identity, which a being reads off the text it was
// written against.
func digestOf(t *testing.T, text string) [32]byte {
	t.Helper()
	bp, err := notation.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return bp.Digest()
}

// named is every being an estate names, flattened, because what a describe
// promises is which beings a voice may reach and never an order.
func named(e warden.Estate) map[[32]byte][32]byte {
	out := map[[32]byte][32]byte{}
	for _, c := range e.Classes {
		for _, one := range c.Beings {
			out[one.Being] = c.Digest
		}
	}
	return out
}

// opened grants a standing at Profile, widens it to Walker before it is
// accepted, and hands back the voice and the beings it names.
func opened(t *testing.T, w *world) (handles []warden.Handle, walker [32]byte) {
	t.Helper()
	inv, err := w.profile.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	held := w.profile.Quo().Standings()
	if len(held) != 1 {
		t.Fatalf("the grant left %d standings", len(held))
	}
	walker = w.walker.Quo().Being()
	if err := w.laptop.Widen(held[0], walker); err != nil {
		t.Fatal(err)
	}
	handles, err = w.rex.Quo().Accept(ctx(), inv, "bob")
	if err != nil {
		t.Fatal(err)
	}
	return handles, walker
}

// A standing names beings, so accepting one answers a handle per being it
// names, and the caller tells them apart by what each handle reaches and what
// each declares.
func TestAcceptingAStandingAnswersAHandlePerBeing(t *testing.T) {
	w := village(t)
	handles, walker := opened(t, w)
	if len(handles) != 2 {
		t.Fatalf("a standing naming two beings answered %d handles", len(handles))
	}

	at := map[[32]byte]warden.Handle{}
	for _, h := range handles {
		at[h.Being()] = h
	}
	profile, ok := at[w.profile.Quo().Being()]
	if !ok {
		t.Fatal("no handle reaches Profile")
	}
	reached, ok := at[walker]
	if !ok {
		t.Fatal("no handle reaches Walker")
	}
	// Each handle is built from its own being's class, so each declares what
	// that class declares and nothing of the other's.
	if v, ok := profile.Call(ctx(), "rate"); !ok || v.(int64) != 20 {
		t.Fatalf("Profile's rate answered %v %v", v, ok)
	}
	if v, ok := reached.Call(ctx(), "secret"); !ok || v.(string) != "nobody sees this" {
		t.Fatalf("Walker's secret answered %v %v", v, ok)
	}
	if _, ok := profile.Call(ctx(), "secret"); ok {
		t.Fatal("Walker's field answered through Profile's handle")
	}
	// Every handle it hands back spends the one relation the accept stood up.
	if n := len(w.walker.Quo().Standings()); n != 1 {
		t.Fatalf("Walker holds %d standings", n)
	}
}

// Describe at a handle is the estate the far door shows this voice: what the
// row names and never the rest of the house. Sketch is the being's own, and a
// blueprint is answered only for a class this voice reaches a being of.
func TestAHandleDescribesWhatTheRowNamesAndNoMore(t *testing.T) {
	w := village(t)
	handles, walker := opened(t, w)
	profile := handles[0]
	if profile.Being() != w.profile.Quo().Being() {
		profile = handles[1]
	}

	estate, ok := profile.Describe(ctx())
	if !ok {
		t.Fatal("the far door did not describe")
	}
	shown := named(estate)
	// The two beings the standing names, and the public being every estate
	// carries. Nothing else of Bob's house.
	if len(shown) != 3 {
		t.Fatalf("the estate names %d beings", len(shown))
	}
	for _, want := range [][32]byte{w.profile.Quo().Being(), walker, w.laptop.Self()} {
		if _, held := shown[want]; !held {
			t.Fatalf("the estate does not name %x", want[:4])
		}
	}
	if _, held := shown[w.inbox.Quo().Being()]; held {
		t.Fatal("Bob's estate named a being of Alice's")
	}

	sketch, ok := profile.Sketch(ctx())
	if !ok {
		t.Fatal("the far door did not sketch")
	}
	if sketch.Being != w.profile.Quo().Being() || sketch.Digest != digestOf(t, profileText) {
		t.Fatalf("the sketch is %#v", sketch)
	}

	text, ok := profile.Blueprint(ctx(), digestOf(t, profileText))
	if !ok || text != profileText {
		t.Fatalf("the class answered %q %v", text, ok)
	}
	// A class this voice reaches no being of is silence: a door that answered
	// any digest put to it could be asked what it runs.
	if text, ok := profile.Blueprint(ctx(), digestOf(t, recordText)); ok {
		t.Fatalf("a class nothing here reaches answered %q", text)
	}
	if limit, ok := profile.Limit(ctx()); !ok || limit != w.laptop.Limit() {
		t.Fatalf("the far door's limit answered %v %v", limit, ok)
	}
}

// The refusal, as strictly as the acceptance: a being narrowed out of the
// standing is a being this voice no longer reaches, and every introspection at
// the handle still pointing there falls silent with the calls.
func TestAHandleAtANarrowedBeingFallsSilent(t *testing.T) {
	w := village(t)
	handles, walkerPk := opened(t, w)
	walker := handles[0]
	if walker.Being() != walkerPk {
		walker = handles[1]
	}
	held := w.walker.Quo().Standings()
	if len(held) != 1 {
		t.Fatalf("Walker holds %d standings", len(held))
	}
	if err := w.laptop.Narrow(held[0], walkerPk); err != nil {
		t.Fatal(err)
	}

	if _, ok := walker.Call(ctx(), "secret"); ok {
		t.Fatal("a narrowed being still answers")
	}
	if _, ok := walker.Sketch(ctx()); ok {
		t.Fatal("a narrowed being was sketched")
	}
	if _, ok := walker.Blueprint(ctx(), digestOf(t, walkerText)); ok {
		t.Fatal("a class this voice no longer reaches was named")
	}
	// The standing is not gone, only narrower, so describe still answers — with
	// Walker no longer in it.
	estate, ok := walker.Describe(ctx())
	if !ok {
		t.Fatal("the far door did not describe")
	}
	if _, still := named(estate)[walkerPk]; still {
		t.Fatal("the estate still names the narrowed being")
	}
}

// A being holding a card knocks, and what it gets is a handle at the far
// door's public being, held as a stranger. The estate that door shows a
// stranger is what the knock answers with, and nothing else.
func TestAKnockIsShownThePublicBeingAndNothingElse(t *testing.T) {
	w := village(t)
	// Bob has granted Alice nothing. The card carries no standing whatsoever.
	door, err := w.rex.Quo().Knock(w.laptop.Card(w.laptop.Hints()), "bob-door")
	if err != nil {
		t.Fatal(err)
	}
	if door.Being() != w.laptop.Self() {
		t.Fatal("the knock reaches something other than the far door")
	}

	estate, ok := door.Describe(ctx())
	if !ok {
		t.Fatal("the far door did not describe to a stranger")
	}
	shown := named(estate)
	if len(shown) != 1 || shown[w.laptop.Self()] != warden.Digest {
		t.Fatalf("a stranger was shown %d beings", len(shown))
	}
	if _, held := shown[w.profile.Quo().Being()]; held {
		t.Fatal("a stranger was shown a granted being")
	}

	sketch, ok := door.Sketch(ctx())
	if !ok {
		t.Fatal("the door did not sketch itself")
	}
	if sketch.Being != w.laptop.Self() || sketch.Digest != warden.Digest {
		t.Fatalf("the door's own sketch is %#v", sketch)
	}
	if limit, ok := door.Limit(ctx()); !ok || limit != w.laptop.Limit() {
		t.Fatalf("the limit answered %v %v", limit, ok)
	}
	// The one blueprint nobody authors is the one a stranger may read, because
	// it is the class of the one being it reaches.
	if text, ok := door.Blueprint(ctx(), warden.Digest); !ok || text != warden.Own.Text() {
		t.Fatalf("the public class answered %q %v", text, ok)
	}
	if _, ok := door.Blueprint(ctx(), digestOf(t, profileText)); ok {
		t.Fatal("a stranger was named a class it reaches no being of")
	}
	// Nothing but the door: re-reading a knock finds no being to hold.
	reread, err := w.rex.Quo().Reread(ctx(), "bob-door")
	if err != nil {
		t.Fatal(err)
	}
	if len(reread) != 0 {
		t.Fatalf("a stranger's re-read found %d beings", len(reread))
	}
	// And the door itself is still under the label: it is in no estate, so a
	// re-read that described it away would take the knock back.
	if again := w.rex.Quo().Relation("bob-door"); again == nil || again.Being() != w.laptop.Self() {
		t.Fatal("the re-read dropped the handle the knock stood up")
	}
}

// A standing widened after it was accepted is re-read from the far door rather
// than remembered: nobody is told it grew, so the holder finds what was added
// by describing again.
func TestAWidenedStandingIsRereadFromTheFarDoor(t *testing.T) {
	w := village(t)
	inv, err := w.profile.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handles, err := w.rex.Quo().Accept(ctx(), inv, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(handles) != 1 {
		t.Fatalf("a standing naming one being answered %d handles", len(handles))
	}

	held := w.profile.Quo().Standings()
	if len(held) != 1 {
		t.Fatalf("Profile holds %d standings", len(held))
	}
	walker := w.walker.Quo().Being()
	if err := w.laptop.Widen(held[0], walker); err != nil {
		t.Fatal(err)
	}
	// Nothing arrived to say so: the handles the accept handed back are still
	// the ones it handed back.
	if n := len(w.rex.Quo().Relations("bob")); n != 1 {
		t.Fatalf("the label holds %d handles before the re-read", n)
	}

	after, err := w.rex.Quo().Reread(ctx(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("the re-read found %d beings", len(after))
	}
	added := after[0]
	if added.Being() != walker {
		added = after[1]
	}
	if added.Being() != walker {
		t.Fatal("the re-read did not reach the being that was added")
	}
	if v, ok := added.Call(ctx(), "secret"); !ok || v.(string) != "nobody sees this" {
		t.Fatalf("the added being answered %v %v", v, ok)
	}
	if n := len(w.rex.Quo().Relations("bob")); n != 2 {
		t.Fatalf("the label holds %d handles after the re-read", n)
	}
}

// A label names every being the standing opened, so a restart that lost all
// but one of them would leave a holder reaching less than it accepted.
func TestALabelKeepsEveryBeingItAcceptedAcrossARestart(t *testing.T) {
	d := warden.NewMemory()
	store := &warden.MemoryStore{}
	holderSeeds := seeds()
	granter := open(t, d, seeds(), nil)
	holder := open(t, d, holderSeeds, store)
	d.Attach("mem://granter", granter)
	d.Attach("mem://holder", holder)
	granter.Publish("mem://granter")
	holder.Publish("mem://holder")

	profile, walker := &Profile{}, &Walker{}
	if _, _, err := granter.Hold(profile, warden.Holding{Blueprint: profileText}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := granter.Hold(walker, warden.Holding{Blueprint: walkerText}); err != nil {
		t.Fatal(err)
	}
	inv, err := profile.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := granter.Widen(profile.Quo().Standings()[0], walker.Quo().Being()); err != nil {
		t.Fatal(err)
	}
	if handles, err := holder.Accept(ctx(), inv, warden.Accepting{Label: "bob"}); err != nil || len(handles) != 2 {
		t.Fatalf("the accept answered %d handles: %v", len(handles), err)
	}

	again := open(t, d, holderSeeds, store)
	d.Attach("mem://holder", again)
	after := again.Relations("bob")
	if len(after) != 2 {
		t.Fatalf("the restart kept %d handles under the label", len(after))
	}
	for _, h := range after {
		at := h.Being()
		if _, ok := h.Sketch(ctx()); !ok {
			t.Fatalf("a handle restored under the label did not sketch %x", at[:4])
		}
	}
}

// The same-warden path keeps one shape, so it answers the same four values a
// handle at a stranger's being answers — read off this warden's own tables,
// scoped to the being the handle reaches.
func TestTheSameWardenPathAnswersTheSameIntrospection(t *testing.T) {
	w := village(t)
	pupPk, pup, err := w.rex.Quo().Hold(&Dog{dogName: "Pup"}, warden.Holding{Blueprint: dogText, Label: "pup"})
	if err != nil {
		t.Fatal(err)
	}

	// The far end of the same being: Bob takes a standing at Pup and holds it
	// through a road, where every step is paid.
	inv, err := w.rex.Quo().Grant(&pupPk)
	if err != nil {
		t.Fatal(err)
	}
	far, err := sole(w.walker.Quo().Accept(ctx(), inv, "pup"))
	if err != nil {
		t.Fatal(err)
	}

	beside, ok := pup.Sketch(ctx())
	if !ok {
		t.Fatal("a being beside me did not sketch")
	}
	across, ok := far.Sketch(ctx())
	if !ok {
		t.Fatal("the far door did not sketch")
	}
	if beside != across {
		t.Fatalf("the two paths sketch %#v and %#v", beside, across)
	}
	if beside.Being != pupPk || beside.Digest != digestOf(t, dogText) {
		t.Fatalf("the sketch is %#v", beside)
	}

	if here, ok := pup.Limit(ctx()); !ok || here != w.phone.Limit() {
		t.Fatalf("the limit beside me answered %v %v", here, ok)
	}
	if there, ok := far.Limit(ctx()); !ok || there != w.phone.Limit() {
		t.Fatalf("the limit across answered %v %v", there, ok)
	}

	// The estate a handle beside me describes is the one a standing naming that
	// being alone is shown: the being, and the public being every estate
	// carries.
	shown, ok := pup.Describe(ctx())
	if !ok {
		t.Fatal("a being beside me did not describe")
	}
	beings := named(shown)
	if len(beings) != 2 {
		t.Fatalf("the estate beside me names %d beings", len(beings))
	}
	if _, held := beings[pupPk]; !held {
		t.Fatal("the estate beside me does not name the being the handle reaches")
	}
	if _, held := beings[w.rex.Quo().Being()]; held {
		t.Fatal("a handle beside me described a being it does not reach")
	}

	if text, ok := pup.Blueprint(ctx(), digestOf(t, dogText)); !ok || text != dogText {
		t.Fatalf("the class beside me answered %q %v", text, ok)
	}
	if _, ok := pup.Blueprint(ctx(), digestOf(t, walkerText)); ok {
		t.Fatal("a class this handle reaches no being of was named beside me")
	}
	// A released being answers nothing, on this path as on any other.
	w.rex.Quo().Release(pupPk)
	if _, ok := pup.Sketch(ctx()); ok {
		t.Fatal("a released being was sketched")
	}
	if _, ok := pup.Describe(ctx()); ok {
		t.Fatal("a released being described a house")
	}
}

func TestCellsAndTakeAreTheContract(t *testing.T) {
	rex := &Dog{dogName: "Rex"}
	rex.LogWalk(7)
	rex.LogWalk(8)
	again := &Dog{dogName: "Rex"}
	if err := again.Take(rex.Cells()); err != nil {
		t.Fatal(err)
	}
	if len(again.walks) != 2 || again.walks[0] != 7 || again.walks[1] != 8 {
		t.Fatalf("the cells moved %v", again.walks)
	}
}
