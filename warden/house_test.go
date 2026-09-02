package warden_test

import (
	"bytes"
	"errors"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// What a warden owes its own house, as against what it owes the wire. Nothing
// below moves a byte between strangers: every case here asserts that the
// answer is what it always was, and that the house learned something beside
// it.

// claim is the claimant's own keys: an arm is for a ground whose keys were
// never minted on this machine, so the bench mints them the way that ground
// would and the door meets them for the first time in the claim.
func claimVoice() [32]byte { return arithmetic.SigningKey(secret("claimant")) }

// armed hands the door a commitment over the granted being, hashed under the
// name the door wears now.
func (g *ground) armed() [32]byte {
	commitment := arithmetic.Commit(g.w.Name(), claimVoice())
	g.w.Arm(commitment, warden.Arming{Beings: [][32]byte{g.being}})
	return commitment
}

// claim is the message that proves an armed commitment: the claimant's own
// voice, signing, carrying the fresh commitment every rotation carries.
func (g *ground) claim(voiceSecret [32]byte, seq int64) []byte {
	g.t.Helper()
	next := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("claimantHeir")))
	s := g.say(arithmetic.SigningKey(voiceSecret), seq)
	s.Commitment = &next
	return g.judge(voiceSecret, s)
}

// TestAnArmedCommitmentIsClaimedOnce holds what an arm is: a claim the door
// will take a standing over for, held at the door and never as a row, spent by
// the first message that proves it.
func TestAnArmedCommitmentIsClaimedOnce(t *testing.T) {
	g := stand(t)
	g.armed()

	// An arm is nobody's standing until it is proved: the only voice standing
	// at the being is the one the invitation minted.
	if before := g.w.Standings(g.being); len(before) != 1 {
		t.Fatalf("an arm wrote %d standings where it should write none", len(before)-1)
	}
	if warden.ArmsHeld(g.w) != 1 {
		t.Fatal("the arm is not held")
	}

	estate := mustEstate(t, g.answer(g.claim(secret("claimant"), 1)))
	if len(estate.Classes) != 2 {
		t.Fatalf("the claim was answered a house of %d classes", len(estate.Classes))
	}
	if warden.ArmsHeld(g.w) != 0 {
		t.Fatal("the arm was not spent")
	}
	if after := g.w.Standings(g.being); len(after) != 2 || !slicesHas(after, claimVoice()) {
		t.Fatalf("the claimant does not stand at the being: %d holders", len(after))
	}

	// Spent means spent. A second ground proving the same commitment is a
	// voice found nowhere, so it is answered as any stranger is — the
	// commitment it carries is ignored, not refused — and it takes nothing.
	held := len(g.w.Standings(g.being))
	g.answer(g.claim(secret("second claimant"), 1))
	if after := g.w.Standings(g.being); len(after) != held {
		t.Fatal("a second claim on a spent arm took a standing")
	}
	if warden.ArmsHeld(g.w) != 0 {
		t.Fatal("a second claim put the arm back")
	}
}

// TestAWrongProofLeavesTheArmWhereItWas holds the refusal: a claim that hashes
// to nothing armed is a voice found nowhere, answered as any stranger is, and
// it costs the arm nothing.
func TestAWrongProofLeavesTheArmWhereItWas(t *testing.T) {
	g := stand(t)
	g.armed()
	held := len(g.w.Standings(g.being))
	g.answer(g.claim(secret("impostor"), 1))
	if warden.ArmsHeld(g.w) != 1 {
		t.Fatal("a wrong proof spent the arm")
	}
	if after := g.w.Standings(g.being); len(after) != held {
		t.Fatal("a wrong proof took a standing")
	}
	// And the arm is still good for the voice it was minted for.
	g.answer(g.claim(secret("claimant"), 1))
}

// TestAnArmNeverTakesAStandingAway holds the order the claim is judged in: the
// inbound record first, so a commitment armed over a voice that already stands
// here cannot take that voice's standing over.
func TestAnArmNeverTakesAStandingAway(t *testing.T) {
	g := stand(t)
	g.rotate(1)
	// The holder's own voice, armed for a being it does not reach.
	g.w.Arm(arithmetic.Commit(g.w.Name(), g.inv.Heir), warden.Arming{})
	// It is still the holder, and still reaches what it was granted.
	if estate := mustEstate(t, g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 2)))); len(estate.Classes) != 2 {
		t.Fatal("the holder lost its standing to an arm")
	}
	if warden.ArmsHeld(g.w) != 1 {
		t.Fatal("an ask spent an arm")
	}
}

// TestForgetDropsOneRelation holds the single row drop: a being's relations at
// one far house go, and its relations elsewhere stay, without a host reaching
// into the record.
func TestForgetDropsOneRelation(t *testing.T) {
	g := stand(t)
	one := arithmetic.SigningKey(secret("far one"))
	two := arithmetic.SigningKey(secret("far two"))
	for _, far := range [][32]byte{one, two} {
		g.w.Stand(g.being, wire.Invitation{Warden: far, Padlock: g.returned}, secret("outward voice"))
	}

	if dropped := g.w.Forget(g.being, &one); dropped != 1 {
		t.Fatalf("forgetting one house dropped %d rows", dropped)
	}
	if _, _, _, _, ok := g.w.RelationAt(one); ok {
		t.Fatal("the forgotten relation is still held")
	}
	if _, _, _, _, ok := g.w.RelationAt(two); !ok {
		t.Fatal("forgetting one house took another with it")
	}
	// A being nobody stands for drops nothing, and the whole drop is the rest.
	if dropped := g.w.Forget(g.w.Self(), nil); dropped != 0 {
		t.Fatalf("another being's rows were dropped: %d", dropped)
	}
	if dropped := g.w.Forget(g.being, nil); dropped != 1 {
		t.Fatalf("the whole drop dropped %d rows", dropped)
	}
}

// TestStandingsAreVoicesAlone holds what a being's own layer may read: who
// holds a standing at it, as pks, and nothing of the door's bookkeeping. A
// being this door does not hold answers empty rather than refusing.
func TestStandingsAreVoicesAlone(t *testing.T) {
	g := stand(t)
	holders := g.w.Standings(g.being)
	if len(holders) != 1 || holders[0] != arithmetic.SigningKey(secret("voice")) {
		t.Fatalf("the granted voice is not the holder listed: %d", len(holders))
	}
	// The list is a copy: writing to it reaches nothing the warden holds.
	holders[0] = [32]byte{}
	if again := g.w.Standings(g.being); again[0] != arithmetic.SigningKey(secret("voice")) {
		t.Fatal("the list reached back into the record")
	}
	if unknown := g.w.Standings(arithmetic.SigningKey(secret("nobody"))); len(unknown) != 0 {
		t.Fatal("an unknown being was said to have holders")
	}
}

// panicky is a being that falls over rather than answering, which is the fault
// an answering layer most wants back.
type panicky struct{ warden.Attach }

func (panicky) Add(string) string { panic("the being fell over") }
func (panicky) Count() int64      { panic("the being fell over") }

// TestSilenceIsObservedInward holds the two directions apart: outward every
// refusal is the same nothing, inward the house is told which step it was and
// what it was about.
func TestSilenceIsObservedInward(t *testing.T) {
	g := stand(t)
	var seen []warden.Silence
	g.w.Observe(func(s warden.Silence) { seen = append(seen, s) })
	g.rotate(1)

	// A field the blueprint never declared, on a being that is reached.
	being := g.being
	s := g.say(g.inv.Heir, 2)
	s.Being = &being
	s.Method = &envelope.Method{Name: "drop", Args: nil}
	g.silent(g.judge(g.inv.HeirSecret, s))

	if len(seen) != 1 {
		t.Fatalf("the house was told of %d silences", len(seen))
	}
	if seen[0].Reason == nil || seen[0].Method != "drop" || seen[0].Being == nil || *seen[0].Being != being {
		t.Fatalf("the silence did not name where it happened: %#v", seen[0])
	}

	// A leash refusal is the same one place, and names no method it never read.
	spent := g.say(g.inv.Heir, 3)
	spent.Allowance = envelope.Allowance{Time: 0, Hops: 0}
	g.silent(g.judge(g.inv.HeirSecret, spent))
	if len(seen) != 2 || seen[1].Method != "" {
		t.Fatalf("the leash silence was not observed plainly: %#v", seen)
	}
}

// TestABeingThatFallsOverIsSilence holds the door as the global recover: a
// being that panics is the same silence as every other refusal, and the house
// hears why.
func TestABeingThatFallsOverIsSilence(t *testing.T) {
	g := stand(t)
	fell, _, err := g.w.Hold(&panicky{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("fell"), HeirSecret: secret("fellHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.rotate(1)
	if err := g.w.Widen(g.inv.Heir, fell); err != nil {
		t.Fatal(err)
	}
	var seen []warden.Silence
	g.w.Observe(func(s warden.Silence) { seen = append(seen, s) })

	s := g.say(g.inv.Heir, 2)
	s.Being = &fell
	s.Method = &envelope.Method{Name: "count"}
	g.silent(g.judge(g.inv.HeirSecret, s))
	if len(seen) != 1 || seen[0].Method != "count" {
		t.Fatalf("the panic was not observed as a silence: %#v", seen)
	}
}

// TestAWatcherThatFallsOverChangesNothing holds the containment: what the house
// does with a fault is the house's problem, and the wire never learns of it.
func TestAWatcherThatFallsOverChangesNothing(t *testing.T) {
	g := stand(t)
	g.w.Observe(func(warden.Silence) { panic("the watcher fell over") })
	g.w.Offer(func(warden.Caller) { panic("the consumer fell over") })
	g.rotate(1)
	g.silent(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 1)))
}

// TestTheWireIsTheSameWatchedAndUnwatched holds the whole promise of the two
// inward surfaces: byte for byte, the answer a caller gets is what it was.
func TestTheWireIsTheSameWatchedAndUnwatched(t *testing.T) {
	plain := stand(t)
	watched := stand(t)
	watched.w.Observe(func(warden.Silence) {})
	watched.w.Offer(func(warden.Caller) {})
	fallen := stand(t)
	fallen.w.Offer(func(warden.Caller) { panic("the consumer fell over") })

	want := plain.rotate(1)
	for _, g := range []*ground{watched, fallen} {
		if got := g.rotate(1); !bytes.Equal(got, want) {
			t.Fatal("the answer differs because the house was listening")
		}
	}
}

// TestTheCallerIsOfferedInward holds Article I as amended: the warden hands the
// voice it just verified to the house, per call, once the caller is placed and
// before the call is routed — a fact and never a judgment.
func TestTheCallerIsOfferedInward(t *testing.T) {
	g := stand(t)
	var seen []warden.Caller
	g.w.Offer(func(c warden.Caller) { seen = append(seen, c) })

	// The rotation: a fresh key taking the standing over.
	g.rotate(1)
	// The holder: the same key, asking plainly.
	g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, 2)))
	// The stranger: a voice that stands nowhere, describing the house.
	g.answer(g.judge(secret("passer-by"), g.say(arithmetic.SigningKey(secret("passer-by")), 1)))

	want := []warden.Caller{
		{Voice: g.inv.Heir, Kind: warden.CallerRotation},
		{Voice: g.inv.Heir, Kind: warden.CallerHolder},
		{Voice: arithmetic.SigningKey(secret("passer-by")), Kind: warden.CallerStranger},
	}
	if len(seen) != len(want) {
		t.Fatalf("the house was offered %d callers", len(seen))
	}
	for at := range want {
		if seen[at] != want[at] {
			t.Fatalf("caller %d was offered as %#v", at, seen[at])
		}
	}
}

// TestAClaimIsOfferedAsARotation holds the other fresh-key path: a voice that
// arrived by proving an armed commitment is offered the same way an heir is.
func TestAClaimIsOfferedAsARotation(t *testing.T) {
	g := stand(t)
	g.armed()
	var seen []warden.Caller
	g.w.Offer(func(c warden.Caller) { seen = append(seen, c) })
	g.answer(g.claim(secret("claimant"), 1))
	if len(seen) != 1 || seen[0] != (warden.Caller{Voice: claimVoice(), Kind: warden.CallerRotation}) {
		t.Fatalf("the claimant was offered as %#v", seen)
	}
}

// TestNewsIsNotACaller holds the exclusion: a peer announcing a succession is
// calling nobody's layer, so nothing is offered inward for it.
func TestNewsIsNotACaller(t *testing.T) {
	g := stand(t)
	far := arithmetic.SigningKey(secret("far one"))
	g.w.Stand(g.being, wire.Invitation{
		Warden:     far,
		Commitment: arithmetic.Commit(far, arithmetic.SigningKey(secret("far heir"))),
		Padlock:    g.returned,
	}, secret("outward voice"))
	offered := 0
	g.w.Offer(func(warden.Caller) { offered++ })

	// A word that says nothing is refused, but it is placed as news first,
	// which is all this case needs: the offer happens after placement.
	s := g.say(far, 1)
	s.Method = &envelope.Method{Name: warden.FieldTell, Args: nil}
	g.silent(g.judge(secret("far one"), s))
	if offered != 0 {
		t.Fatal("news was offered inward as a caller")
	}
}

// TestTheDoorRoutesByTheBlueprint holds the scope: a name the blueprint never
// declared is not reached for on the object at all, so a being cannot be made
// to answer for a field it never published.
func TestTheDoorRoutesByTheBlueprint(t *testing.T) {
	g := stand(t)
	reached := &loud{}
	being, _, err := g.w.Hold(reached, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("loud"), HeirSecret: secret("loudHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.rotate(1)
	if err := g.w.Widen(g.inv.Heir, being); err != nil {
		t.Fatal(err)
	}
	s := g.say(g.inv.Heir, 2)
	s.Being = &being
	s.Method = &envelope.Method{Name: "drop"}
	g.silent(g.judge(g.inv.HeirSecret, s))
	if reached.touched {
		t.Fatal("the object was touched for a field its blueprint never declared")
	}
}

// loud answers anything and says it was asked, so a case can tell a refusal at
// the door from a refusal by the object.
type loud struct {
	warden.Attach
	touched bool
}

func (o *loud) Add(string) (string, error) {
	o.touched = true
	return "", errors.New("the being answered")
}

func (o *loud) Count() (int64, error) {
	o.touched = true
	return 0, errors.New("the being answered")
}

// TestARefusalThisKitMadeItselfSpendsNoNumber holds the count against the far
// door: a hop that put nothing on the wire spends nothing at a door that never
// heard of it.
func TestARefusalThisKitMadeItselfSpendsNoNumber(t *testing.T) {
	g := stand(t)
	far := arithmetic.SigningKey(secret("far one"))
	g.w.Stand(g.being, wire.Invitation{Warden: far, Padlock: g.returned}, secret("outward voice"))

	// A hint the wire will not carry: the refusal is this kit's own, made
	// before a byte is sealed.
	if _, _, err := g.w.Ask(warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Hints:     []string{"\xff"},
	}); err == nil {
		t.Fatal("the kit sealed a message it should have refused")
	}
	// A leash with nothing left is the same: refused here, sent nowhere.
	if _, _, err := g.w.Ask(warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: 0, Hops: 0},
	}); err == nil {
		t.Fatal("a call with no leash was composed")
	}

	// The first message that is actually sent is number one.
	_, seq, err := g.w.Ask(warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("a refusal this kit made itself burned a number: the first sent is %d", seq)
	}
	// And a message that is sent does spend one.
	if _, next, err := g.w.Ask(warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); err != nil || next != 2 {
		t.Fatalf("a sent message spent %d (%v)", next, err)
	}
}

func slicesHas(keys [][32]byte, want [32]byte) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}
