package warden_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/notation"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// The judgment produces almost no bytes, so the corpus cannot measure it.
// Everything below is asserted from the law's own words.

const todoText = "ToDo\n  add(title text) text\n  count() int\n"

// todo is an ordinary Go value. Its arguments arrive decoded and its answers
// leave as plain values: it never sees a byte, a key or a road.
type todo struct {
	warden.Attach
	items []string
}

// todoFrom is what a house that welcomes this class does with a cargo: it makes
// the being from the cells that travelled with it, which is the whole of what
// the origin sent that is not identity or record.
func todoFrom(cells []byte) (any, error) {
	o := &todo{}
	if len(cells) > 0 {
		o.items = strings.Split(string(cells), "\n")
	}
	return o, nil
}

func (o *todo) Add(title string) string {
	o.items = append(o.items, title)
	return title
}

func (o *todo) Count() int64 { return int64(len(o.items)) }

// keyType and textType are the two argument types this bench encodes by hand.
func keyType() notation.Type  { return notation.Type{Kind: notation.KindB32} }
func textType() notation.Type { return notation.Type{Kind: notation.KindText} }

// secret is a fixed thirty-two byte draw, so nothing here is random or timed.
func secret(label string) [32]byte { return arithmetic.Hash([]byte("quo-go-bench/" + label)) }

// tick is a clock the bench holds and moves by hand, in milliseconds. A door's
// clock is taken as an argument for the same reason a draw of randomness is:
// a kit that reached for the wall clock could not be pinned to a test.
type tick struct{ ms int64 }

func (c *tick) read() int64   { return c.ms }
func (c *tick) step(ms int64) { c.ms += ms }

// fixed is the randomness a door with nothing to assert about its draws is
// handed: a sequence, so nothing here is random and two runs are one run.
func fixed(label string) func() [32]byte {
	at := 0
	return func() [32]byte {
		at++
		return secret(fmt.Sprintf("%s/draw/%d", label, at))
	}
}

type ground struct {
	t        *testing.T
	w        *warden.Warden
	clock    *tick
	being    [32]byte
	inv      wire.Invitation
	returned [32]byte // the caller's return padlock
	opens    [32]byte // and the secret that opens what comes back to it
	// supply is the randomness this door was handed at open, primed per
	// judgment in the order a judgment draws: the answer's ephemeral key
	// first, then the two keys a receive mints. A bench that could not name
	// them could not assert what a receive did with them.
	supply []([32]byte)
	drawn  int
}

// draw is the door's randomness. What the case in hand primed comes first, and
// anything drawn past it is a fixed sequence, so nothing here is random.
func (g *ground) draw() [32]byte {
	if len(g.supply) > 0 {
		one := g.supply[0]
		g.supply = g.supply[1:]
		return one
	}
	g.drawn++
	return secret(fmt.Sprintf("draw/%d", g.drawn))
}

func stand(t *testing.T) *ground {
	t.Helper()
	return standWith(t, 1<<20, nil)
}

func standLimited(t *testing.T, limit int64) *ground {
	t.Helper()
	return standWith(t, limit, nil)
}

// standDelivered is stand with delivery handed in, for the cases where this
// ground has to be able to speak first.
func standDelivered(t *testing.T, delivery warden.Delivery) *ground {
	t.Helper()
	return standWith(t, 1<<20, delivery)
}

func standWith(t *testing.T, limit int64, delivery warden.Delivery) *ground {
	t.Helper()
	clock := &tick{}
	g := &ground{t: t, clock: clock}
	w, err := warden.New(warden.Founding{
		NameSecret:     secret("name"),
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(secret("name")), arithmetic.SigningKey(secret("wardenHeir"))),
		PadlockSecret:  secret("padlock"),
		Limit:          limit,
		Clock:          clock.read,
		Random:         g.draw,
		Delivery:       delivery,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.w = w
	being, _, err := w.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("being"), HeirSecret: secret("beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// This house can make a being of that class, which is what lets a being of
	// it migrate here at all.
	if _, err := w.Welcome(todoText, todoFrom); err != nil {
		t.Fatal(err)
	}
	returned, err := arithmetic.SealingKey(secret("returnPadlock"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := w.GrantAs(being, warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")}, w.Padlock(), []string{"https://one.example"})
	if err != nil {
		t.Fatal(err)
	}
	g.being, g.inv, g.returned, g.opens = being, inv, returned, secret("returnPadlock")
	return g
}

// say builds a well-formed utterance to this door, which each case then bends.
func (g *ground) say(voice [32]byte, seq int64) envelope.Say {
	return envelope.Say{
		Voice:     voice,
		Recipient: g.w.Name(),
		Seq:       seq,
		Padlock:   g.returned,
		Hints:     []string{"https://caller.example"},
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}
}

// own names the warden's own public being, whose pk is the warden's own name.
// Every field on it — blueprint, limit, moved, tell, receive — is reached by
// naming the being it sits on, like every other field on every other being.
func (g *ground) own() *[32]byte {
	k := g.w.Name()
	return &k
}

// judge seals a say under the signer's key and runs the eight steps over it.
func (g *ground) judge(signer [32]byte, s envelope.Say) []byte {
	g.t.Helper()
	message, err := envelope.SealSay(secret("ephemeral"), g.w.Padlock(), signer, s)
	if err != nil {
		g.t.Fatal(err)
	}
	// The keys this judgment may draw, in the order it draws them.
	g.supply = []([32]byte){secret("answerEphemeral"), secret("receiveBeing"), secret("receiveHeir")}
	reply := g.w.Arrive(message, nil)
	g.supply = nil
	return reply
}

// answer opens what came back and hands over the data the field answered.
func (g *ground) answer(reply []byte) []byte {
	g.t.Helper()
	if reply == nil {
		g.t.Fatal("silence where an answer was due")
	}
	a, err := envelope.OpenAnswer(g.opens, reply)
	if err != nil {
		g.t.Fatalf("the answer would not open: %v", err)
	}
	if a.Warden != g.w.Name() {
		g.t.Fatal("the answer is not signed by the door that was asked")
	}
	return a.Data
}

// silent asserts the whole of every refusal, which is what the wire gets: no
// answer and no word about which step it was. Why the door fell silent is the
// house's own channel, asserted where a case registers one.
func (g *ground) silent(reply []byte) {
	g.t.Helper()
	if reply != nil {
		g.t.Fatal("a door that should have said nothing spoke")
	}
}

// rotate is the holder's first act: the heir spends and takes the standing over.
func (g *ground) rotate(seq int64) []byte {
	g.t.Helper()
	next := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("ownHeir")))
	s := g.say(g.inv.Heir, seq)
	s.Commitment = &next
	return g.answer(g.judge(g.inv.HeirSecret, s))
}

// TestRotateAndAsk holds the whole of granting: the two kinds of call are told
// apart at the door by the signature alone, and rotation is a prefix on an ask.
func TestRotateAndAsk(t *testing.T) {
	g := stand(t)
	estate := mustEstate(t, g.rotate(1))

	// The public being is reachable by everyone, holders included, so it
	// appears in every estate beside the being that was granted.
	if len(estate.Classes) != 2 {
		t.Fatalf("the estate holds %d classes", len(estate.Classes))
	}
	found := false
	for _, c := range estate.Classes {
		for _, h := range c.Beings {
			if h.Being == g.being {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("the granted being is not in the estate it was granted for")
	}

	// Past the rotation the same key asks plainly, and the old key is dead.
	if data := g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 2))); len(data) == 0 {
		t.Fatal("the plain ask answered nothing")
	}
	// Dead means the row no longer mentions it, which drops it to the
	// stranger's case rather than to a refusal: it still gets an answer, and
	// that answer is a house with one room in it.
	dead := mustEstate(t, g.answer(g.judge(secret("voice"), g.say(arithmetic.SigningKey(secret("voice")), 3))))
	if len(dead.Classes) != 1 || dead.Classes[0].Beings[0].Being != g.w.Self() {
		t.Fatalf("the dead key was shown %#v", dead)
	}
}

// TestTheOldSecretIsSpentOnce holds that a standing is transferred, never
// copied: the moment someone takes the voice over the previous key is dead,
// and the heir cannot spend twice because its commitment was replaced.
func TestTheOldSecretIsSpentOnce(t *testing.T) {
	g := stand(t)
	g.rotate(1)
	next := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("ownHeir")))
	s := g.say(g.inv.Heir, 2)
	s.Commitment = &next
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// TestARotationWithNoCommitmentIsRefused holds the standing rule where the
// law names the harm but not the verdict: a rotation carrying no fresh
// commitment is a standing that could be taken over once and never again.
func TestARotationWithNoCommitmentIsRefused(t *testing.T) {
	g := stand(t)
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 1)))
}

// TestAnAskCarryingACommitmentIsRefused holds the other half: the commitment
// is present only when the message spends an heir.
func TestAnAskCarryingACommitmentIsRefused(t *testing.T) {
	g := stand(t)
	g.rotate(1)
	stray := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("stray")))
	s := g.say(g.inv.Heir, 2)
	s.Commitment = &stray
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// wayBack reads the padlock the door holds for the granted voice, which is the
// only place a standing's way back is visible from outside the kit.
func (g *ground) wayBack() [32]byte {
	g.t.Helper()
	cargo, err := g.w.Pack(g.being, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	if len(cargo.Standings) != 1 || cargo.Standings[0].Padlock == nil {
		g.t.Fatalf("no way back on the one standing: %+v", cargo.Standings)
	}
	return *cargo.Standings[0].Padlock
}

// roads reads the hints the door holds for the granted voice, the other half of
// a standing's way back.
func (g *ground) roads() []string {
	g.t.Helper()
	cargo, err := g.w.Pack(g.being, nil)
	if err != nil {
		g.t.Fatal(err)
	}
	if len(cargo.Standings) != 1 {
		g.t.Fatalf("no way back on the one standing: %+v", cargo.Standings)
	}
	return cargo.Standings[0].Hints
}

// TestAnArrivingCallWithEmptyHintsLeavesTheWayBackStanding holds Article VII's
// mirror of Article XIV: an empty hints list means the road did not change,
// never an erasure. An end that publishes nothing — the dialing end always —
// sends empty hints by nature, and a door that erased on that would destroy its
// own way back to that peer on the peer's first ask.
func TestAnArrivingCallWithEmptyHintsLeavesTheWayBackStanding(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldLimit}
	g.answer(g.judge(g.inv.HeirSecret, s))
	if roads := g.roads(); len(roads) != 1 || roads[0] != "https://caller.example" {
		t.Fatalf("the way back did not take the road the call carried: %v", roads)
	}

	empty := g.say(g.inv.Heir, 3)
	empty.Hints = nil
	empty.Being = g.own()
	empty.Method = &envelope.Method{Name: warden.FieldLimit}
	g.answer(g.judge(g.inv.HeirSecret, empty))
	if roads := g.roads(); len(roads) != 1 || roads[0] != "https://caller.example" {
		t.Fatalf("an empty hints list erased the way back: %v", roads)
	}
}

// TestTheWayBackIsRefreshedBetweenTheSeqAndTheLeash holds where the refresh
// falls, which decides two things a door would otherwise get wrong. Both are
// consequences of the placement rather than choices of their own.
func TestTheWayBackIsRefreshedBetweenTheSeqAndTheLeash(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	live, err := arithmetic.SealingKey(secret("livePadlock"))
	if err != nil {
		t.Fatal(err)
	}
	s := g.say(g.inv.Heir, 5)
	s.Padlock = live
	// The answer is sealed to the padlock the call carried, so it is not this
	// bench's to open. That it was answered at all is the whole of what this
	// step needs.
	if g.judge(secret("voiceHeir"), s) == nil {
		t.Fatal("silence where an answer was due")
	}
	if g.wayBack() != live {
		t.Fatal("the way back did not move to what the call carried")
	}

	// Not earlier than the seq: a replayed message carries whatever way back
	// the peer had when it was sent, and the seq is the only thing that tells
	// a replay from a call. A door that refreshed first would let anyone
	// holding a copy overwrite a live way back with a retired one.
	retired, err := arithmetic.SealingKey(secret("retiredPadlock"))
	if err != nil {
		t.Fatal(err)
	}
	replay := g.say(g.inv.Heir, 5)
	replay.Padlock = retired
	g.silent(g.judge(secret("voiceHeir"), replay))
	if g.wayBack() != live {
		t.Fatal("a refused replay rewrote the way back")
	}

	// And not later than the leash: a message refused for its leash still
	// arrived and still spent its number. A door that refreshed only what it
	// went on to route would slowly lose the way back to any peer whose calls
	// it keeps refusing — and news is what that peer would stop receiving.
	late, err := arithmetic.SealingKey(secret("latePadlock"))
	if err != nil {
		t.Fatal(err)
	}
	leashed := g.say(g.inv.Heir, 6)
	leashed.Padlock = late
	leashed.Allowance = envelope.Allowance{Time: 0, Hops: 4}
	g.silent(g.judge(secret("voiceHeir"), leashed))
	if g.wayBack() != late {
		t.Fatal("refused for its leash, and the way back stood still")
	}
}

// TestAStrangerCarryingACommitmentIsTheStrangersCase holds Article XII's step
// four: the kind is read off the voice and never declared, so a commitment the
// message carries changes none of it. A door that refused would meet the
// holder whose door has forgotten it with silence, where the stranger's case
// tells that caller the house is alive.
func TestAStrangerCarryingACommitmentIsTheStrangersCase(t *testing.T) {
	g := stand(t)
	nobody := arithmetic.SigningKey(secret("nobody"))
	stray := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("strayHeir")))

	for _, carried := range []*[32]byte{nil, &stray} {
		s := g.say(nobody, 1)
		s.Commitment = carried
		estate := mustEstate(t, g.answer(g.judge(secret("nobody"), s)))
		// A stranger's estate is the warden's own public being and nothing
		// else, whichever spelling arrived.
		if len(estate.Classes) != 1 || len(estate.Classes[0].Beings) != 1 {
			t.Fatalf("a stranger saw %d classes", len(estate.Classes))
		}
		if estate.Classes[0].Beings[0].Being != g.w.Name() {
			t.Fatal("a stranger saw something that is not the public being")
		}
	}
}

// TestACommitmentIsVerifiedAtTheNameItWasMintedUnder holds what a commitment
// is: the hash of the pk of the warden the heir would spend at, then the
// heir's. A door that succeeded its name and hashed at the name it wears now
// would find nothing for every standing it granted before — so each row keeps
// the name its own commitment was minted under, in memory and on no wire.
func TestACommitmentIsVerifiedAtTheNameItWasMintedUnder(t *testing.T) {
	g := stand(t)
	mintedAt := g.w.Name()

	// The heavy rotation: the heir the founding committed to spends, and the
	// house signs by that key from here on. A key that is not that heir cannot.
	after := arithmetic.SigningKey(secret("wardenHeirTwo"))
	if err := g.w.Succeed(secret("stray"), arithmetic.Commit(mintedAt, after)); err == nil {
		t.Fatal("a key that was never committed took the house's name")
	}
	succeeded := arithmetic.SigningKey(secret("wardenHeir"))
	if err := g.w.Succeed(secret("wardenHeir"), arithmetic.Commit(succeeded, after)); err != nil {
		t.Fatal(err)
	}
	if g.w.Name() == mintedAt || g.w.Name() != succeeded {
		t.Fatal("the house did not take its heir's name")
	}

	// The older standing still rotates. Its heir hashes to the commitment at
	// the old name, and hashing at the door's current name would find nothing.
	next := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("ownHeir")))
	s := g.say(g.inv.Heir, 1)
	s.Commitment = &next
	g.answer(g.judge(g.inv.HeirSecret, s))

	// And the commitment it just made is minted under the name the door has
	// now, so the chain runs on rather than stopping at the succession.
	last := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("ownHeirTwo")))
	s = g.say(arithmetic.SigningKey(secret("ownHeir")), 1)
	s.Commitment = &last
	g.answer(g.judge(secret("ownHeir"), s))
}

// TestTheSeqSpendsOnce holds the window: above the mark is honoured and moves
// it, inside the window is honoured once and never again, below it is silence.
func TestTheSeqSpendsOnce(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 9)))
	// A message that merely arrived late is still honoured.
	g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 5)))
	// Once, and never again.
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 5)))
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 9)))
	// The first legal number is one.
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 0)))
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, -1)))
}

// TestANumberStaysSpent holds that a message refused at routing has still
// consumed its number, so a door is never replayable through its own refusals.
func TestANumberStaysSpent(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	stranger := [32]byte{9}
	s := g.say(g.inv.Heir, 2)
	s.Being = &stranger
	g.silent(g.judge(g.inv.HeirSecret, s))

	// The same number, now well-routed, is gone.
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 2)))
}

// TestTheRecipientBindsTheMessage holds step three: a message presented at
// any other door is silence.
func TestTheRecipientBindsTheMessage(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	s := g.say(g.inv.Heir, 2)
	s.Recipient = [32]byte{7}
	g.silent(g.judge(g.inv.HeirSecret, s))

	// A door that never named its house can still be spoken to first, so the
	// padlock binds as well as the name.
	s = g.say(g.inv.Heir, 3)
	s.Recipient = g.w.Padlock()
	g.answer(g.judge(g.inv.HeirSecret, s))
}

// TestTheLeashIsSpent holds step six, judged on what arrived: a budget at or
// below zero, or a hop count below zero, is silence. A hop count of zero is
// not — it is a legal leash for a call that goes no further, and what it
// forbids is onward.
func TestTheLeashIsSpent(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	s := g.say(g.inv.Heir, 2)
	s.Allowance.Hops = -1
	g.silent(g.judge(g.inv.HeirSecret, s))

	s = g.say(g.inv.Heir, 3)
	s.Allowance.Time = 0
	g.silent(g.judge(g.inv.HeirSecret, s))

	s = g.say(g.inv.Heir, 4)
	s.Allowance.Time = -1
	g.silent(g.judge(g.inv.HeirSecret, s))

	// Zero hops arrives and is judged. The door answers, because this call goes
	// no further.
	s = g.say(g.inv.Heir, 5)
	s.Allowance.Hops = 0
	g.answer(g.judge(g.inv.HeirSecret, s))
}

// TestTheStrangerGetsOneRoom holds the stranger's case: no standing anywhere,
// and the estate is the warden's own public being. A stranger gets a house
// with one room in it.
func TestTheStrangerGetsOneRoom(t *testing.T) {
	g := stand(t)
	voice := arithmetic.SigningKey(secret("passerby"))

	estate := mustEstate(t, g.answer(g.judge(secret("passerby"), g.say(voice, 1))))
	if len(estate.Classes) != 1 || len(estate.Classes[0].Beings) != 1 {
		t.Fatalf("the stranger was shown %#v", estate)
	}
	if estate.Classes[0].Digest != warden.Digest || estate.Classes[0].Beings[0].Being != g.w.Self() {
		t.Fatal("the one room is not the warden's own being")
	}

	// A stranger spends nothing: no mark is kept for it, so its numbers are
	// not counted and a repeat is not a replay.
	g.answer(g.judge(secret("passerby"), g.say(voice, 1)))

	// What it may not reach, it is not told about.
	s := g.say(voice, 1)
	s.Being = &g.being
	g.silent(g.judge(secret("passerby"), s))
}

// TestAnExposedBeingIsReachedByAStranger holds the other half of the one room:
// a ground decides what it offers a voice that merely knocks, and until it
// says so the answer is the warden's own being alone.
func TestAnExposedBeingIsReachedByAStranger(t *testing.T) {
	g := stand(t)
	voice := arithmetic.SigningKey(secret("passerby"))

	// Not exposed: the stranger reaches nothing of it.
	s := g.say(voice, 1)
	s.Being = &g.being
	g.silent(g.judge(secret("passerby"), s))

	if !g.w.Expose(g.being) {
		t.Fatal("the warden would not expose a being it holds")
	}
	// Exposing a being it does not hold is refused rather than kept.
	if g.w.Expose([32]byte{9}) {
		t.Fatal("the warden exposed a being it does not hold")
	}

	estate := mustEstate(t, g.answer(g.judge(secret("passerby"), g.say(voice, 1))))
	if len(estate.Classes) != 2 {
		t.Fatalf("the stranger was shown %d classes rather than two", len(estate.Classes))
	}
	// And the being answers the stranger, which is the point of exposing it.
	s = g.say(voice, 1)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "count", Args: []byte{}}
	g.answer(g.judge(secret("passerby"), s))

	// A stranger still spends no number and holds no row: exposure is not a
	// standing, and the same envelope is not a replay.
	g.answer(g.judge(secret("passerby"), s))

	// Concealed, it is silence again and the house has one room.
	if !g.w.Conceal(g.being) {
		t.Fatal("the warden would not conceal what it had exposed")
	}
	g.silent(g.judge(secret("passerby"), s))
	estate = mustEstate(t, g.answer(g.judge(secret("passerby"), g.say(voice, 1))))
	if len(estate.Classes) != 1 {
		t.Fatalf("the stranger was shown %d classes after concealing", len(estate.Classes))
	}
}

// TestTheDoorPublishesItsLimit holds the only fact this document makes a
// warden publish about itself, and that a caller need not learn by silence.
func TestTheDoorPublishesItsLimit(t *testing.T) {
	g := stand(t)
	voice := arithmetic.SigningKey(secret("passerby"))
	s := g.say(voice, 1)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldLimit, Args: []byte{}}
	data := g.answer(g.judge(secret("passerby"), s))
	if !bytes.Equal(data, []byte{0, 0, 0, 0, 0, 16, 0, 0}) {
		t.Fatalf("the limit came back as %x", data)
	}
}

// TestSketchIsScopedLikeEverythingElse holds that every describe is scoped by
// the same binary record, without exception — and that the refusal is silence
// rather than an absent optional, because absence would confirm the being.
func TestSketchIsScopedLikeEverythingElse(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	s := g.say(g.inv.Heir, 2)
	s.Being = &g.being
	sketch := mustSketch(t, g.answer(g.judge(g.inv.HeirSecret, s)))
	if sketch.Being != g.being {
		t.Fatal("the sketch names another being")
	}

	unknown := [32]byte{4}
	s = g.say(g.inv.Heir, 3)
	s.Being = &unknown
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// TestABlueprintIsAnsweredOnlyToWhoReachesIt holds the probe the law names:
// a door that answered any digest put to it would be a door that could be
// asked what it runs.
func TestABlueprintIsAnsweredOnlyToWhoReachesIt(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	s := g.say(g.inv.Heir, 2)
	s.Being = &g.being
	digest := mustSketch(t, g.answer(g.judge(g.inv.HeirSecret, s))).Digest

	arg, err := wire.Encode(warden.Own, keyType(), digest)
	if err != nil {
		t.Fatal(err)
	}
	s = g.say(g.inv.Heir, 3)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldBlueprint, Args: arg}
	text := mustText(t, g.answer(g.judge(g.inv.HeirSecret, s)))
	if text != todoText {
		t.Fatalf("the blueprint came back as %q", text)
	}
	// It verifies: content-addressed text cannot be swapped by whoever carried it.
	if arithmetic.Hash([]byte(text)) != digest {
		t.Fatal("the text does not hash to the digest it was asked for")
	}

	// A stranger holds no standing at that class, so the same ask is silence.
	voice := arithmetic.SigningKey(secret("passerby"))
	s = g.say(voice, 1)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldBlueprint, Args: arg}
	g.silent(g.judge(secret("passerby"), s))
}

// TestTheBeingIsInvokedAndNeverJudges holds that the object is handed the call
// and answers, and that the warden never looks inside the blob.
func TestTheBeingIsInvokedAndNeverJudges(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	args, err := wire.Encode(warden.Own, textType(), "milk")
	if err != nil {
		t.Fatal(err)
	}
	s := g.say(g.inv.Heir, 2)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "add", Args: args}
	if data := g.answer(g.judge(g.inv.HeirSecret, s)); !bytes.Equal(data, args) {
		t.Fatalf("the being answered %x", data)
	}

	// A being that breaks fails inside its warden, and the caller gets the
	// same silence as one who may not ask.
	s = g.say(g.inv.Heir, 3)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "kick", Args: []byte{}}
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// TestMovedAnswersAbsence holds silence and absence apart: an absent optional
// is a legal answer to a legal ask, so moved answers absence when nothing has
// moved — and a word once published is answered by `moved` alone, never put in
// place of work.
func TestMovedAnswersAbsence(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	arg, err := wire.Encode(warden.Own, keyType(), g.being)
	if err != nil {
		t.Fatal(err)
	}
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldMoved, Args: arg}
	if data := g.answer(g.judge(g.inv.HeirSecret, s)); !bytes.Equal(data, []byte{0}) {
		t.Fatalf("moved answered %x where absence was due", data)
	}

	successor := arithmetic.SigningKey(secret("successor"))
	next := arithmetic.Commit(successor, successor)
	g.w.Point(g.being, warden.Word{
		Being: &g.being, Successor: &successor, Commitment: &next, Hints: []string{"https://new.example"},
	})
	s = g.say(g.inv.Heir, 3)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldMoved, Args: arg}
	data := g.answer(g.judge(g.inv.HeirSecret, s))
	if len(data) == 0 || data[0] != 1 {
		t.Fatalf("moved answered %x where the word was due", data)
	}
	word, err := warden.DecodeWord(data[1:])
	if err != nil {
		t.Fatal(err)
	}
	if word.Successor == nil || *word.Successor != successor {
		t.Fatal("the word points nowhere")
	}

	// The old door only points: every ask that is not `moved` meets silence,
	// because a succession is not the answer type the field declared. It never
	// forwards and never acts again.
	s = g.say(g.inv.Heir, 4)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "count", Args: []byte{}}
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// TestNewsIsBelievedByAKeyAlreadyHeld holds the whole of the news section: a
// succession proved against the commitment, a padlock replacement proved by
// the name, and anything else silence.
func TestNewsIsBelievedByAKeyAlreadyHeld(t *testing.T) {
	// A peer's ground, holding a relation with a far house.
	peer, err := warden.New(warden.Founding{
		NameSecret:     secret("peerName"),
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(secret("peerName")), arithmetic.SigningKey(secret("peerHeir"))),
		PadlockSecret:  secret("peerPadlock"),
		Clock:          (&tick{}).read,
		Random:         fixed("peer"),
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &ground{t: t, w: peer}
	g.returned, err = arithmetic.SealingKey(secret("peerReturn"))
	if err != nil {
		t.Fatal(err)
	}
	g.opens = secret("peerReturn")

	far := arithmetic.SigningKey(secret("farName"))
	farHeir := arithmetic.SigningKey(secret("farHeir"))
	farPadlock, err := arithmetic.SealingKey(secret("farPadlock"))
	if err != nil {
		t.Fatal(err)
	}
	peer.Stand(peer.Self(), wire.Invitation{
		Warden:     far,
		Commitment: arithmetic.Commit(far, farHeir),
		Padlock:    farPadlock,
		Hints:      []string{"https://far.example"},
	}, secret("peerVoice"))

	tell := func(signer [32]byte, seq int64, word warden.Word) []byte {
		t.Helper()
		args, err := warden.EncodeWord(word)
		if err != nil {
			t.Fatal(err)
		}
		s := g.say(arithmetic.SigningKey(signer), seq)
		s.Being = g.own()
		s.Method = &envelope.Method{Name: warden.FieldTell, Args: args}
		return g.judge(signer, s)
	}

	// A padlock replacement: nothing is succeeded, so it is signed by the name
	// and carries only the new lock.
	lock, err := arithmetic.SealingKey(secret("farPadlock2"))
	if err != nil {
		t.Fatal(err)
	}
	if data := g.answer(tell(secret("farName"), 1, warden.Word{Padlock: &lock})); data != nil {
		t.Fatalf("tell answered %x where it answers nothing", data)
	}
	if _, _, padlock, _, _ := peer.RelationAt(far); padlock != lock {
		t.Fatal("the padlock was not replaced")
	}

	// A padlock replacement can be replayed, so it is counted.
	g.silent(tell(secret("farName"), 1, warden.Word{Padlock: &lock}))

	// A stranger's word hashes to nothing this peer holds.
	g.silent(tell(secret("impostor"), 1, warden.Word{Padlock: &lock}))

	// News may name no being at all: a method with no being reaches the
	// warden's own being, which is where tell sits. A granting warden sending
	// news has never had a describe from its peer, so the door alone is the
	// only address it is sure of, and that address has to work.
	args, err := warden.EncodeWord(warden.Word{Padlock: &lock})
	if err != nil {
		t.Fatal(err)
	}
	s := g.say(arithmetic.SigningKey(secret("farName")), 2)
	s.Method = &envelope.Method{Name: warden.FieldTell, Args: args}
	if data := g.answer(g.judge(secret("farName"), s)); data != nil {
		t.Fatalf("tell answered %x where it answers nothing", data)
	}

	// Naming some other being is still silence: news is the warden's own
	// affair and no other being holds a tell.
	other := [32]byte{9}
	s = g.say(arithmetic.SigningKey(secret("farName")), 3)
	s.Being = &other
	s.Method = &envelope.Method{Name: warden.FieldTell, Args: args}
	g.silent(g.judge(secret("farName"), s))

	// A name succession: the successor signs and the peer hashes. It carries
	// the same number the old key already spent, and is honoured — a
	// succession starts the news mark fresh, because the old key died with
	// its count.
	nextHeir := arithmetic.SigningKey(secret("farHeir2"))
	next := arithmetic.Commit(farHeir, nextHeir)
	g.answer(tell(secret("farHeir"), 1, warden.Word{
		Successor: &farHeir, Commitment: &next, Name: &farHeir,
	}))
	if _, commitment, _, _, ok := peer.RelationAt(farHeir); !ok || commitment != next {
		t.Fatal("the relation was not rewritten onto the successor")
	}
	if _, _, _, _, ok := peer.RelationAt(far); ok {
		t.Fatal("the dead name still names a relation")
	}

	// And a house that persists continues its mark from there.
	lock2, err := arithmetic.SealingKey(secret("farPadlock3"))
	if err != nil {
		t.Fatal(err)
	}
	g.silent(tell(secret("farHeir"), 1, warden.Word{Padlock: &lock2}))
	g.answer(tell(secret("farHeir"), 2, warden.Word{Padlock: &lock2}))

	// A word that says nothing is silence.
	g.silent(tell(secret("farHeir"), 3, warden.Word{Hints: []string{"https://nowhere"}}))

	// A word naming the far warden's own pk as a being is refused, even where
	// the peer has been handed a commitment under that pk: the name and the
	// public being are one key, so such a word would be a second spelling of
	// the name's own succession — which `being` absent already says — and a
	// value with two spellings is two identities.
	after := arithmetic.SigningKey(secret("farHeir3"))
	afterNext := arithmetic.Commit(nextHeir, after)
	if err := peer.Learn(farHeir, farHeir, next); err != nil {
		t.Fatal(err)
	}
	g.silent(tell(secret("farHeir2"), 4, warden.Word{
		Being: &farHeir, Successor: &nextHeir, Commitment: &afterNext,
	}))
	// And the row is untouched: the succession said the other way still stands.
	if _, commitment, _, _, ok := peer.RelationAt(farHeir); !ok || commitment != next {
		t.Fatal("a refused word moved the relation")
	}

	// The committed heir cannot replace the lock, though it is a key this peer
	// holds and is placed as news by it. Article XIV gives this act exactly one
	// signer — the name, which has not moved — and a door that believed any key
	// it managed to place would let a house's heir replace that house's lock at
	// every peer before succeeding anything, so every message those peers sent
	// next would be sealed to a lock the heir chose. That is key substitution
	// by a party the law deliberately gave no such power.
	stolen, err := arithmetic.SealingKey(secret("heirsOwnLock"))
	if err != nil {
		t.Fatal(err)
	}
	g.silent(tell(secret("farHeir2"), 5, warden.Word{Padlock: &stolen}))
	if _, _, padlock, _, _ := peer.RelationAt(farHeir); padlock != lock2 {
		t.Fatal("the committed heir replaced the house's lock at this peer")
	}
	// The name signs the same word and it is believed, so what refused the
	// first is the signer and nothing else about the word.
	if data := g.answer(tell(secret("farHeir"), 6, warden.Word{Padlock: &stolen})); data != nil {
		t.Fatalf("tell answered %x where it answers nothing", data)
	}
	if _, _, padlock, _, _ := peer.RelationAt(farHeir); padlock != stolen {
		t.Fatal("the name could not replace its own lock")
	}

	// Nor may the committed heir hand the relation to a third party: the
	// successor signs and the peer hashes, so a word naming a successor the
	// signer is not proves nothing about that key.
	thief := arithmetic.SigningKey(secret("thiefName"))
	theirs := arithmetic.Commit(thief, arithmetic.SigningKey(secret("thiefHeir")))
	g.silent(tell(secret("farHeir2"), 7, warden.Word{
		Successor: &thief, Commitment: &theirs, Name: &thief,
	}))
	if _, _, _, _, ok := peer.RelationAt(thief); ok {
		t.Fatal("a key that never signed for it was handed the relation")
	}
	if _, commitment, _, _, ok := peer.RelationAt(farHeir); !ok || commitment != next {
		t.Fatal("a refused word moved the relation")
	}

	// A commitment on the envelope is ignored rather than refused. Article XI
	// names two refusals on that field — a plain ask carrying one, a rotation
	// carrying none — and they are the only two: each has a mechanical reason
	// in step 4, and neither reason exists for news, which places a voice by
	// the outbound record and never reads the field. A door that refused it
	// would meet a house that has succeeded with silence, and a house that has
	// succeeded and is not believed is a house nobody can reach.
	stray := arithmetic.Commit(farHeir, arithmetic.SigningKey(secret("stray")))
	args, err = warden.EncodeWord(warden.Word{Padlock: &stolen})
	if err != nil {
		t.Fatal(err)
	}
	s = g.say(arithmetic.SigningKey(secret("farHeir")), 8)
	s.Commitment = &stray
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldTell, Args: args}
	if data := g.answer(g.judge(secret("farHeir"), s)); data != nil {
		t.Fatalf("tell answered %x where it answers nothing", data)
	}
	// And the field decided nothing: the row's commitment is what the word
	// last said, never what the envelope carried.
	if _, commitment, _, _, ok := peer.RelationAt(farHeir); !ok || commitment != next {
		t.Fatal("a commitment on a news envelope was read as a claim")
	}
}

// TestABeingSuccessionNeedsItsOwnCommitment holds what the invitation does not
// carry: a peer believes a being's succession against the commitment the
// describe handed it, and holds none until it has been given one.
func TestABeingSuccessionNeedsItsOwnCommitment(t *testing.T) {
	peer, err := warden.New(warden.Founding{
		NameSecret:     secret("peer2Name"),
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(secret("peer2Name")), arithmetic.SigningKey(secret("peer2Heir"))),
		PadlockSecret:  secret("peer2Padlock"),
		Clock:          (&tick{}).read,
		Random:         fixed("peer2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	g := &ground{t: t, w: peer}
	g.returned, err = arithmetic.SealingKey(secret("peer2Return"))
	if err != nil {
		t.Fatal(err)
	}
	g.opens = secret("peer2Return")

	far := arithmetic.SigningKey(secret("far2Name"))
	farPadlock, err := arithmetic.SealingKey(secret("far2Padlock"))
	if err != nil {
		t.Fatal(err)
	}
	peer.Stand(peer.Self(), wire.Invitation{
		Warden:     far,
		Commitment: arithmetic.Commit(far, arithmetic.SigningKey(secret("far2Heir"))),
		Padlock:    farPadlock,
	}, secret("peer2Voice"))

	being := arithmetic.SigningKey(secret("far2Being"))
	beingHeir := arithmetic.SigningKey(secret("far2BeingHeir"))
	nextCommitment := arithmetic.Commit(beingHeir, beingHeir)
	word := warden.Word{Being: &being, Successor: &beingHeir, Commitment: &nextCommitment}

	tell := func(signer [32]byte, seq int64) []byte {
		t.Helper()
		args, err := warden.EncodeWord(word)
		if err != nil {
			t.Fatal(err)
		}
		s := g.say(arithmetic.SigningKey(signer), seq)
		s.Being = g.own()
		s.Method = &envelope.Method{Name: warden.FieldTell, Args: args}
		return g.judge(signer, s)
	}

	// Held nothing for that being: the voice is not placed at all.
	g.silent(tell(secret("far2BeingHeir"), 1))

	if err := peer.Learn(far, being, arithmetic.Commit(far, beingHeir)); err != nil {
		t.Fatal(err)
	}
	g.answer(tell(secret("far2BeingHeir"), 1))
}

// TestReceiveNeedsTheOrdinaryGate holds the one field the law gates by hand:
// a door any stranger could push a being into is a door with no gate, and no
// new gate is needed when the ordinary one serves. Its answer is the
// commitment of the key the destination minted and the origin never saw.
func TestReceiveNeedsTheOrdinaryGate(t *testing.T) {
	g := stand(t)

	arriving := arithmetic.SigningKey(secret("arriving"))
	cargo, err := warden.EncodeCargo(warden.Cargo{
		Being:  arriving,
		Digest: arithmetic.Hash([]byte(todoText)),
		Cells:  []byte("state"),
		Standings: []warden.Standing{{
			Voice:      arithmetic.SigningKey(secret("follower")),
			Commitment: arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("followerHeir"))),
			Beings:     [][32]byte{arriving},
			Mark:       11,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// A stranger is refused before the cargo is even read.
	s := g.say(arithmetic.SigningKey(secret("passerby")), 1)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: cargo}
	g.silent(g.judge(secret("passerby"), s))

	g.rotate(1)
	s = g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: cargo}
	data := g.answer(g.judge(g.inv.HeirSecret, s))
	// A destination mints two keys — the one the being is named by here and
	// that one's heir — and the commitment is of the first (Article IX). The
	// being's new name is where the migration's second news moves the being's
	// identity, and it is what the peer hashes that succession against; a
	// commitment to the heir would name a key that signs nothing until the
	// succession after this one, and the news would be disbelieved.
	arrivedAs := arithmetic.SigningKey(secret("receiveBeing"))
	want := arithmetic.Commit(g.w.Name(), arrivedAs)
	if !bytes.Equal(data, want[:]) {
		t.Fatalf("receive answered %x", data)
	}
	if heirs := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("receiveHeir"))); bytes.Equal(data, heirs[:]) {
		t.Fatal("receive answered the commitment of the new name's heir, not of the new name")
	}

	// The being wears the name this door minted for it, and the standings that
	// travelled reach it there.
	// The record travelled with the being, and the mark with it, so the number
	// the follower had already spent does not come round again at the new door.
	s = g.say(arithmetic.SigningKey(secret("follower")), 11)
	s.Being = &arrivedAs
	g.silent(g.judge(secret("follower"), s))

	s = g.say(arithmetic.SigningKey(secret("follower")), 12)
	s.Being = &arrivedAs
	g.answer(g.judge(secret("follower"), s))

	// And it does not come round once the mark has moved past it either. A
	// mark that arrives in a cargo is a number that was honoured — that is
	// what a mark is — so as the mark moves off it, it belongs in the window
	// beneath as spent. A door that only moved the mark would honour eleven a
	// second time here, which is Article XIII's own named harm arriving one
	// call later than the article's example.
	s = g.say(arithmetic.SigningKey(secret("follower")), 11)
	s.Being = &arrivedAs
	g.silent(g.judge(secret("follower"), s))

	// **An arriving row reaches the being by the name this door minted and by
	// that name alone** (Article XIII), never also by the name it wore before:
	// a name a door must remember for whoever might still be behind is a name
	// it can never stop remembering, and the peer that is behind is not
	// stranded, because the old door still answers `moved`.
	s = g.say(arithmetic.SigningKey(secret("follower")), 13)
	s.Being = &arriving
	g.silent(g.judge(secret("follower"), s))
}

// TestThePublicBeingsPkIsTheWardensOwnName holds the plain sentence: the
// warden is a being, so the key that names the house and the key that names
// the being the house speaks as are one key.
func TestThePublicBeingsPkIsTheWardensOwnName(t *testing.T) {
	g := stand(t)
	if g.w.Self() != g.w.Name() {
		t.Fatal("the public being wears a key of its own")
	}

	// A stranger holds a card, and a card carries the name — so it can address
	// the door with nothing else. That is the whole point of the two keys being
	// one: a separate key would mean a card alone let you reach a door and ask
	// it nothing.
	card := g.w.Card([]string{"https://one.example"})
	if card.Warden != g.w.Self() {
		t.Fatal("the card does not name the being the door speaks as")
	}
	s := g.say(arithmetic.SigningKey(secret("passerby")), 1)
	s.Being = &card.Warden
	s.Method = &envelope.Method{Name: warden.FieldLimit, Args: []byte{}}
	if data := g.answer(g.judge(secret("passerby"), s)); !bytes.Equal(data, []byte{0, 0, 0, 0, 0, 16, 0, 0}) {
		t.Fatalf("the card's own name reached %x", data)
	}

	// It is a being like any other, so naming it with no method is its sketch,
	// and the class it answers is the one blueprint nobody authors.
	s = g.say(arithmetic.SigningKey(secret("passerby")), 2)
	s.Being = &card.Warden
	sketch := mustSketch(t, g.answer(g.judge(secret("passerby"), s)))
	if sketch.Being != g.w.Name() || sketch.Digest != warden.Digest {
		t.Fatalf("the door's own sketch is %#v", sketch)
	}
}

// TestAMethodWithNoBeingReachesTheWardensOwnBeing holds the fifth entry in the
// routing list. Addressing the door alone is how you speak to the ground's own
// affairs, and a caller reaching limit or blueprint should not have to pay a
// describe first to learn the name of the being it is already talking to.
func TestAMethodWithNoBeingReachesTheWardensOwnBeing(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	arg, err := wire.Encode(warden.Own, keyType(), g.being)
	if err != nil {
		t.Fatal(err)
	}
	// Every field of the warden's own being answers with no being named, and
	// answers exactly what it answers when the door's name is written out.
	for i, m := range []envelope.Method{
		{Name: warden.FieldDescribe, Args: []byte{}},
		{Name: warden.FieldLimit, Args: []byte{}},
		{Name: warden.FieldMoved, Args: arg},
		{Name: warden.FieldSketch, Args: arg},
	} {
		bare := g.say(g.inv.Heir, int64(2+2*i))
		bare.Method = &m
		named := g.say(g.inv.Heir, int64(3+2*i))
		named.Being = g.own()
		named.Method = &m
		if a, b := g.answer(g.judge(g.inv.HeirSecret, bare)), g.answer(g.judge(g.inv.HeirSecret, named)); !bytes.Equal(a, b) {
			t.Fatalf("%s answered %x with no being and %x with the door named", m.Name, a, b)
		}
	}

	// A field no blueprint of the warden's declares is still silence: the door
	// alone is an address, not a wildcard onto every being it holds.
	s := g.say(g.inv.Heir, 20)
	s.Method = &envelope.Method{Name: "add", Args: []byte{}}
	g.silent(g.judge(g.inv.HeirSecret, s))

	// A stranger reaches it too, because the public being is the one being
	// every warden already has and it describes itself to whoever knocks.
	s = g.say(arithmetic.SigningKey(secret("passerby")), 1)
	s.Method = &envelope.Method{Name: warden.FieldLimit, Args: []byte{}}
	if data := g.answer(g.judge(secret("passerby"), s)); !bytes.Equal(data, []byte{0, 0, 0, 0, 0, 16, 0, 0}) {
		t.Fatalf("a stranger reached limit and got %x", data)
	}

	// Neither being nor method is still the estate, not a describe by another
	// road: the absent method is what makes it one.
	mustEstate(t, g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 21))))
}

// TestDistanceZeroWaivesNoStepOfTheJudgment holds Article III's last word: a
// call handed straight to the judge, same process, no wire, still runs the
// whole judgment. The well-formed ask answers, and the same ask meets the
// same silence a stranger's box would when its signature is corrupted or
// its number has already been spent — distance zero is a carriage, not a
// shortcut through the steps.
func TestDistanceZeroWaivesNoStepOfTheJudgment(t *testing.T) {
	g := stand(t)
	g.rotate(1)

	// The local road works: a well-formed sealed ask, handed to the judge in
	// the same process, answers.
	args, err := wire.Encode(warden.Own, textType(), "milk")
	if err != nil {
		t.Fatal(err)
	}
	s := g.say(g.inv.Heir, 2)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "add", Args: args}
	if data := g.answer(g.judge(g.inv.HeirSecret, s)); !bytes.Equal(data, args) {
		t.Fatalf("the being answered %x", data)
	}

	// A signature corrupted in transit meets silence even though there was
	// no transit: the bytes are handed directly, and the judge still checks
	// every one of them.
	s = g.say(g.inv.Heir, 3)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "add", Args: args}
	message, err := envelope.SealSay(secret("ephemeral"), g.w.Padlock(), g.inv.HeirSecret, s)
	if err != nil {
		t.Fatal(err)
	}
	bent := append([]byte(nil), message...)
	bent[len(bent)-1] ^= 1
	g.silent(g.w.Arrive(bent, nil))

	// A replayed envelope meets silence too: the same seq handed to the
	// judge a second time, in the very process that spent it, is still
	// spent.
	g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 4)))
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 4)))
}

// TestThePublishedLimitBindsWhereThereIsNoRoad holds that the one fact a warden
// publishes about itself is judged by the warden. A door whose limit lived only
// in its line would accept, over a road with no socket in it, exactly the
// envelope it told every caller it would refuse.
func TestThePublishedLimitBindsWhereThereIsNoRoad(t *testing.T) {
	measure := standLimited(t, 1<<20)
	measure.rotate(1)
	s := measure.say(measure.inv.Heir, 2)
	s.Being = measure.own()
	s.Method = &envelope.Method{Name: warden.FieldLimit, Args: []byte{}}
	message, err := envelope.SealSay(secret("ephemeral"), measure.w.Padlock(), measure.inv.HeirSecret, s)
	if err != nil {
		t.Fatal(err)
	}

	// A byte over the limit is silence, and it is silence before the record is
	// touched: the same envelope is honoured when the limit admits it, which
	// it could not be had the refused one spent its number.
	over := standLimited(t, int64(len(message))-1)
	over.rotate(1)
	over.silent(over.w.Arrive(message, nil))

	exact := standLimited(t, int64(len(message)))
	exact.rotate(1)
	if back := exact.w.Arrive(message, nil); back == nil {
		t.Fatal("the limit is inclusive, and this door refused its own largest message")
	}
}

func mustEstate(t *testing.T, data []byte) warden.Estate {
	t.Helper()
	e, err := warden.DecodeEstate(data)
	if err != nil {
		t.Fatalf("the estate would not decode: %v", err)
	}
	return e
}

func mustSketch(t *testing.T, data []byte) warden.Sketch {
	t.Helper()
	if len(data) == 0 || data[0] != 1 {
		t.Fatalf("the sketch came back as %x", data)
	}
	s, err := warden.DecodeSketch(data[1:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustText(t *testing.T, data []byte) string {
	t.Helper()
	if len(data) == 0 || data[0] != 1 {
		t.Fatalf("the text came back as %x", data)
	}
	v, err := wire.Decode(warden.Own, textType(), data[1:])
	if err != nil {
		t.Fatal(err)
	}
	return v.(string)
}
