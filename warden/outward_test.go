package warden_test

import (
	"fmt"
	"reflect"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// The inward side of the record — granting, amending, releasing — and the
// outward side of a call — composing one, counting it, and rotating with it.
// Every case is asserted from the law's own words; none of it produces bytes
// the corpus could measure.

// other is a being of a second class, for the cases about what a standing
// reaches rather than about what a being answers.
type other struct{ warden.Attach }

func (other) F() bool { return true }

// estate describes at that number and hands back the classes the holder sees.
func (g *ground) estate(seq int64) []warden.Class {
	g.t.Helper()
	return mustEstate(g.t, g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, seq)))).Classes
}

// house stands a second ground up, so a call has somewhere to come from.
func house(t *testing.T, label string) *warden.Warden {
	t.Helper()
	return housed(t, label, nil)
}

// housed is house with delivery handed in, for the cases that need this ground
// to be able to speak first.
func housed(t *testing.T, label string, delivery warden.Delivery) *warden.Warden {
	t.Helper()
	name := secret(label + "/name")
	at := 0
	w, err := warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(secret(label+"/wardenHeir"))),
		PadlockSecret:  secret(label + "/padlock"),
		Limit:          1 << 20,
		Clock:          (&tick{}).read,
		// A fixed sequence, so nothing here is random: what a case asserts is
		// never the key itself, only that one was drawn where the law says one
		// is drawn.
		Random: func() [32]byte {
			at++
			return secret(fmt.Sprintf("%s/draw/%d", label, at))
		},
		Delivery: delivery,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// TestAStandingIsAmendedNotReplaced holds that widening and narrowing are the
// same act as writing the row: nobody is told, no secret is minted, and the
// holder simply finds more or less the next time it describes.
func TestAStandingIsAmendedNotReplaced(t *testing.T) {
	g := stand(t)
	second, _, err := g.w.Hold(&other{}, warden.Holding{
		Blueprint: "Other\n  f() bool\n",
		Keys:      warden.Keys{Secret: secret("second"), HeirSecret: secret("secondHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.rotate(1)

	// One class at first, beside the warden's own public being.
	if n := len(g.estate(2)); n != 2 {
		t.Fatalf("the estate holds %d classes, want 2", n)
	}
	if err := g.w.Widen(g.inv.Heir, second); err != nil {
		t.Fatal(err)
	}
	if n := len(g.estate(3)); n != 3 {
		t.Fatalf("after widening the estate holds %d classes, want 3", n)
	}
	if err := g.w.Narrow(g.inv.Heir, second); err != nil {
		t.Fatal(err)
	}
	if n := len(g.estate(4)); n != 2 {
		t.Fatalf("after narrowing the estate holds %d classes, want 2", n)
	}
}

// TestTakingTheLastBeingAwayIsRelease holds that there is no separate act for
// it: the holder meets silence, which is the same answer as any refusal.
func TestTakingTheLastBeingAwayIsRelease(t *testing.T) {
	g := stand(t)
	g.rotate(1)
	if err := g.w.Narrow(g.inv.Heir, g.being); err != nil {
		t.Fatal(err)
	}
	// The voice stands nowhere now, so it cannot even be amended.
	if err := g.w.Widen(g.inv.Heir, g.being); err == nil {
		t.Fatal("a voice with no row was widened")
	}
	// It falls to the stranger's case, and a stranger gets a house with one
	// room in it.
	if n := len(g.estate(2)); n != 1 {
		t.Fatalf("a released voice sees %d classes, want 1", n)
	}
}

// TestReleasingABeingTakesItsStandingsWithIt holds the other direction: drop
// the pointer, and the standings go with it.
func TestReleasingABeingTakesItsStandingsWithIt(t *testing.T) {
	g := stand(t)
	g.rotate(1)
	g.w.Release(g.being)
	if n := len(g.estate(2)); n != 1 {
		t.Fatalf("after release the holder sees %d classes, want 1", n)
	}
	// And the being itself is gone, so an ask at it is silence.
	s := g.say(g.inv.Heir, 3)
	s.Being = &g.being
	s.Method = &envelope.Method{Name: "count", Args: []byte{}}
	g.silent(g.judge(g.inv.HeirSecret, s))
}

// TestGrantRefusesAVoiceThatAlreadyStands holds that a standing is transferred
// but never copied: there is one holder, always.
func TestGrantRefusesAVoiceThatAlreadyStands(t *testing.T) {
	g := stand(t)
	if _, err := g.w.GrantAs(g.being, warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")}, g.w.Padlock(), nil); err == nil {
		t.Fatal("one voice was granted twice")
	}
}

// TestGrantRefusesABeingTheWardenDoesNotHold holds that a warden grants only
// at what it keeps.
func TestGrantRefusesABeingTheWardenDoesNotHold(t *testing.T) {
	g := stand(t)
	if _, err := g.w.GrantAs([32]byte{9}, warden.Keys{Secret: secret("v2"), HeirSecret: secret("v2h")}, g.w.Padlock(), nil); err == nil {
		t.Fatal("a warden granted at a being it does not hold")
	}
}

// TestACallCarriesItsOwnLeashAndTheDoorSpendsIt holds the caller's side: a
// call carrying a leash the far door would meet with silence never leaves.
// Zero hops is not one of those — it is a legal leash for a call that goes no
// further — so the near door composes it like any other.
func TestACallCarriesItsOwnLeashAndTheDoorSpendsIt(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	caller.Stand(caller.Self(), g.inv, g.inv.HeirSecret)

	for _, leash := range []envelope.Allowance{{Time: 0, Hops: 8}, {Time: 5000, Hops: -1}, {Time: -1, Hops: -1}} {
		if _, _, err := caller.Ask(warden.Reach{Far: g.inv.Warden, Allowance: leash}); err == nil {
			t.Fatalf("a call with %#v left this ground", leash)
		}
	}
	if _, _, err := caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 0},
	}); err != nil {
		t.Fatalf("a call that goes no further was refused: %v", err)
	}
}

// TestACallNeedsARelation holds that a being holds a handle to a relation and
// never the relation's key: with no row there is nothing to sign with.
func TestACallNeedsARelation(t *testing.T) {
	caller := house(t, "caller")
	if _, _, err := caller.Ask(warden.Reach{
		Far:       [32]byte{9},
		Allowance: envelope.Allowance{Time: 1, Hops: 1},
	}); err == nil {
		t.Fatal("a call left for a house this ground holds no relation with")
	}
}

// TestTheCountOnlyRisesForOneVoice holds the caller's half of the replay rule:
// per voice the number only rises, so the counter lives beside the voice.
func TestTheCountOnlyRisesForOneVoice(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	caller.Stand(caller.Self(), g.inv, g.inv.HeirSecret)

	mine := secret("callerHeir")
	reach := warden.Reach{Far: g.inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}}

	rotate := reach
	rotate.NextHeir = &mine
	if _, seq, err := caller.Ask(rotate); err != nil || seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d (%v), want 1", seq, err)
	}
	for want := int64(2); want <= 4; want++ {
		_, seq, err := caller.Ask(reach)
		if err != nil || seq != want {
			t.Fatalf("spent %d (%v), want %d", seq, err, want)
		}
	}
	// A rotation starts the count fresh, because the old key died with it —
	// which brings number one round again, so the first ask's answer must be
	// out of the awaiting record before the second rotation may be sent.
	caller.Forgo(g.inv.Warden, 1, [32]byte{})
	next := secret("callerHeir2")
	rotate.NextHeir = &next
	if _, seq, err := caller.Ask(rotate); err != nil || seq != 1 {
		t.Fatalf("the second rotation spent %d (%v), want 1", seq, err)
	}
}

// TestARotationCarriesAFreshCommitmentUnderTheFarDoor holds that a rotation
// carrying no fresh commitment is a standing taken over exactly once and never
// again — and that the commitment is hashed under the door the heir would
// spend at, so it is worth nothing anywhere else.
func TestARotationCarriesAFreshCommitmentUnderTheFarDoor(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	caller.Stand(caller.Self(), g.inv, g.inv.HeirSecret)

	mine := secret("callerHeir")
	message, _, err := caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err := envelope.OpenSay(secret("padlock"), message)
	if err != nil {
		t.Fatal(err)
	}
	if say.Commitment == nil {
		t.Fatal("a rotate-and-ask carried no fresh commitment")
	}
	want := arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(mine))
	if *say.Commitment != want {
		t.Fatal("the commitment is not hashed under the door the heir would spend at")
	}
	// A plain ask carries none: the commitment rides only when the message
	// spends an heir.
	message, _, err = caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err = envelope.OpenSay(secret("padlock"), message)
	if err != nil {
		t.Fatal(err)
	}
	if say.Commitment != nil {
		t.Fatal("a plain ask carried a commitment")
	}
}

// TestTheCallerNamesTheDoorAndItsOwnReturnPadlock holds two fields of the say
// at once: the recipient binds the message to one house, and the return
// padlock is the caller's own choice — the same one it gives everybody, or one
// it keeps for this relation alone.
func TestTheCallerNamesTheDoorAndItsOwnReturnPadlock(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	caller.Stand(caller.Self(), g.inv, g.inv.HeirSecret)

	message, _, err := caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err := envelope.OpenSay(secret("padlock"), message)
	if err != nil {
		t.Fatal(err)
	}
	if say.Recipient != g.w.Name() {
		t.Fatal("the call does not name the door it is for")
	}
	if say.Padlock != caller.Padlock() {
		t.Fatal("the default return padlock is not the caller's own")
	}

	// A padlock kept for this relation alone is the whole of what a caller can
	// do about being linked across doors, so it must be the caller's to set.
	// The secret stays in the warden, because a caller that held one outside
	// would be holding the one thing this picture says only a warden holds.
	alone, err := caller.Lock(secret("perRelation"))
	if err != nil {
		t.Fatal(err)
	}
	message, _, err = caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Padlock:   alone,
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err = envelope.OpenSay(secret("padlock"), message)
	if err != nil {
		t.Fatal(err)
	}
	if say.Padlock != alone {
		t.Fatal("the caller's own padlock did not ride")
	}
	// And the caller's warden is not named: the payload carries a padlock and
	// hints and nothing else about the house the caller lives in.
	if say.Voice == caller.Name() {
		t.Fatal("the caller signed with its warden's name rather than a voice")
	}
}

// TestTheAnswerIsSealedToTheReturnPadlock holds step eight, end to end and in
// process: what the door sends back opens under the padlock the payload
// carried, and under nothing else.
func TestTheAnswerIsSealedToTheReturnPadlock(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	caller.Stand(caller.Self(), g.inv, g.inv.HeirSecret)

	// A lock this caller keeps for one relation alone. The secret stays in the
	// warden, because a caller that held one outside would be holding the one
	// thing this picture says only a warden holds.
	alone, err := caller.Lock(secret("perRelation"))
	if err != nil {
		t.Fatal(err)
	}
	mine := secret("callerHeir")
	message, seq, err := caller.Ask(warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Padlock:   alone,
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := g.w.Arrive(message, nil)
	if reply == nil {
		t.Fatal("the door said nothing to an ask it should have answered")
	}
	answer, err := caller.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != g.w.Name() || answer.Seq != seq {
		t.Fatalf("the answer is %#v", answer)
	}
	// And under nothing else: the warden's own lock, which the payload never
	// named, does not open it.
	if _, err := envelope.OpenAnswer(secret("caller/padlock"), reply); err == nil {
		t.Fatal("the answer opened under a padlock the payload never named")
	}
}

// TestAnArrivedBeingAnswers holds the half of a migration everything else here
// assumes: a being that migrated is a being, so a peer that stood at it before
// the move asks it a field of its own blueprint and is answered. A destination
// that took the identity, the cells and both records and put no program behind
// the name it minted would pass every other assertion in this file and leave
// the being addressable and mute.
func TestAnArrivedBeingAnswers(t *testing.T) {
	g := stand(t) // the destination, and the ordinary gate a receive spends

	follower := arithmetic.SigningKey(secret("follower"))
	arriving := arithmetic.SigningKey(secret("arriving"))
	packed, err := warden.EncodeCargo(warden.Cargo{
		Being:  arriving,
		Digest: arithmetic.Hash([]byte(todoText)),
		// The being's own memory, which is what it is made from at the far
		// house: two items it will still count after the move.
		Cells: []byte("milk\neggs"),
		Standings: []warden.Standing{{
			Voice:      follower,
			Commitment: arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("followerHeir"))),
			Beings:     [][32]byte{arriving},
			Mark:       11,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	g.rotate(1)
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: packed}
	g.answer(g.judge(g.inv.HeirSecret, s))

	// The peer reaches the being by the name this door minted and by that name
	// alone, on the standing that travelled and above the mark that travelled
	// with it.
	arrivedAs := arithmetic.SigningKey(secret("receiveBeing"))
	ask := g.say(follower, 12)
	ask.Being = &arrivedAs
	ask.Method = &envelope.Method{Name: "count"}
	data := g.answer(g.judge(secret("follower"), ask))
	if len(data) != 8 || data[7] != 2 {
		t.Fatalf("the arrived being answered %v, want the two items its cells carried", data)
	}

	// And the blueprint is still the scope: a name it never declared is not
	// reached for on the object at all.
	ask = g.say(follower, 13)
	ask.Being = &arrivedAs
	ask.Method = &envelope.Method{Name: "undeclared"}
	g.silent(g.judge(secret("follower"), ask))
}

// TestACargoOfAClassThisHouseCannotMakeIsRefused holds Article IX's one gate on
// a cargo: a destination that does not already hold the class refuses it in
// silence, and there is nobody it may ask. Holding the class is holding the
// program — a house with only the blueprint's text could answer the commitment
// and leave the being unable to act.
func TestACargoOfAClassThisHouseCannotMakeIsRefused(t *testing.T) {
	g := stand(t)

	const other = "Lamp\n  lit() bool\n"
	packed, err := warden.EncodeCargo(warden.Cargo{
		Being:  arithmetic.SigningKey(secret("arriving")),
		Digest: arithmetic.Hash([]byte(other)),
	})
	if err != nil {
		t.Fatal(err)
	}

	g.rotate(1)
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: packed}
	g.silent(g.judge(g.inv.HeirSecret, s))

	// Its text alone is not the class: a house that can hand the blueprint out
	// still cannot make one.
	if _, err := g.w.Welcome(other, nil); err == nil {
		t.Fatal("a class with no maker was welcomed")
	}
}

// TestABeingArrivesAbleToActAgain holds the half of a migration that is easy
// to forget: a being's outbound record travels with it, and the cargo carries
// a relation row for each. A being that only answers would migrate perfectly
// without this; a being that acts would arrive alive and mute, which is not
// the same being.
func TestABeingArrivesAbleToActAgain(t *testing.T) {
	g := stand(t) // the destination, and the ordinary gate a receive spends
	third := house(t, "third")
	room, _, err := third.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("third/room"), HeirSecret: secret("third/roomHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := third.GrantAs(room,
		warden.Keys{Secret: secret("third/voice"), HeirSecret: secret("third/voiceHeir")},
		third.Padlock(), []string{"https://third.example"})
	if err != nil {
		t.Fatal(err)
	}

	// The doors where the being holds a standing know only a voice and have
	// never heard of the being, so nothing there is told and nothing there
	// changes. What travels is the row itself.
	arriving := arithmetic.SigningKey(secret("arriving"))
	cargo := warden.Cargo{
		Being:  arriving,
		Digest: arithmetic.Hash([]byte(todoText)),
		Cells:  []byte("state"),
		Relations: []warden.Relation{{
			Warden:     inv.Warden,
			Commitment: inv.Commitment,
			Padlock:    inv.Padlock,
			Voice:      inv.Heir,
			Secret:     inv.HeirSecret,
			Heir:       inv.Heir,
			HeirSecret: inv.HeirSecret,
			Seq:        0,
			Hints:      inv.Hints,
		}},
	}
	// The cargo rides by the notation's own rules like every other argument.
	packed, err := warden.EncodeCargo(cargo)
	if err != nil {
		t.Fatal(err)
	}
	read, err := warden.DecodeCargo(packed)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Relations) != 1 || !reflect.DeepEqual(read.Relations[0], cargo.Relations[0]) {
		t.Fatalf("the relation did not survive the wire: %#v", read.Relations)
	}

	// Before the cargo lands, this ground stands nowhere at that house.
	if _, _, err := g.w.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); err == nil {
		t.Fatal("a call left for a house this ground holds no relation with")
	}

	g.rotate(1)
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: packed}
	g.answer(g.judge(g.inv.HeirSecret, s))

	// And now it can act: the relation it inherited spends at the third door,
	// and the third door answers. The voice it carried is the heir the third
	// house committed, so the first act is a rotate-and-ask, exactly as any
	// holder's is.
	mine := secret("arrivingNextHeir")
	message, seq, err := g.w.Ask(warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d, want 1", seq)
	}
	reply := third.Arrive(message, nil)
	if reply == nil {
		t.Fatal("the third door refused the arrived being")
	}
	answer, err := g.w.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != third.Name() || answer.Seq != seq {
		t.Fatalf("the answer is %#v", answer)
	}

	// Pack reads the same row back off the record, so a being that moved once
	// can move again — under the name this door minted for it, which is the
	// name the migration's second news moved its identity to.
	arrivedAs := arithmetic.SigningKey(secret("receiveBeing"))
	again, err := g.w.Pack(arrivedAs, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Relations) != 1 || again.Relations[0].Warden != inv.Warden {
		t.Fatalf("the packed relations are %#v", again.Relations)
	}
	if again.Relations[0].Seq != 1 {
		t.Fatalf("the packed count is %d, want the one the being has spent", again.Relations[0].Seq)
	}
	if len(again.Standings) != 0 {
		t.Fatalf("the arrived being carries %d inbound rows, want none", len(again.Standings))
	}
}

// TestTheOriginComposesTheNewsItsPeersAreOwed holds the origin's half of a
// migration, which is the half that has to reach somebody. The cargo lands and
// the destination answers a commitment; what remains is a word to every peer
// that stands at the being, signed by the heir the being committed, and it is
// composed here rather than by the host — a house that packed a cargo and then
// had to invent the announcement itself would invent a different one at every
// ground.
func TestTheOriginComposesTheNewsItsPeersAreOwed(t *testing.T) {
	origin := house(t, "departing")
	peer := house(t, "hearing")
	being, _, err := origin.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("departing/being"), HeirSecret: secret("departing/beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := origin.GrantAs(being,
		warden.Keys{Secret: secret("departing/voice"), HeirSecret: secret("departing/voiceHeir")},
		origin.Padlock(), []string{"https://departing.example"})
	if err != nil {
		t.Fatal(err)
	}
	peer.Stand(peer.Self(), inv, inv.HeirSecret)

	// A peer that has never spoken left no way back: an inbound row keeps the
	// padlock the peer named, and nothing else in Quo tells a door how to reach
	// a voice.
	if told := origin.Peers(being); len(told) != 1 || told[0].Padlock != nil {
		t.Fatalf("a peer that has never spoken left a way back: %#v", told)
	}
	mine := secret("departing/peerNextHeir")
	message, _, err := peer.Ask(warden.Reach{
		Far:       origin.Name(),
		Being:     &being,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &mine,
		Hints:     []string{"https://hearing.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if origin.Arrive(message, nil) == nil {
		t.Fatal("the origin said nothing to the peer's ask")
	}
	told := origin.Peers(being)
	if len(told) != 1 || told[0].Padlock == nil || *told[0].Padlock != peer.Padlock() {
		t.Fatalf("the way back was not read off the call that arrived: %#v", told)
	}

	// The peer holds the being's own commitment, handed over by a describe.
	// Without it there is no material to believe this being's succession with.
	successor := arithmetic.SigningKey(secret("departing/beingHeir"))
	if err := peer.Learn(origin.Name(), being, arithmetic.Commit(origin.Name(), successor)); err != nil {
		t.Fatal(err)
	}

	// What `receive` answered at the far house, which is the one fact the
	// origin carries into the news and cannot invent.
	landed := house(t, "landing")
	commitment := arithmetic.Commit(landed.Name(), arithmetic.SigningKey(secret("landing/arrived")))

	// A key this being never committed to composes news nobody can believe, so
	// it is refused here rather than sent.
	if _, err := origin.Depart(being, warden.Departing{
		HeirSecret: secret("departing/nobody"), Commitment: commitment,
		Name: landed.Name(), Padlock: landed.Padlock(),
	}); err == nil {
		t.Fatal("the origin departed on a key the being never committed to")
	}

	departed, err := origin.Depart(being, warden.Departing{
		HeirSecret: secret("departing/beingHeir"),
		Commitment: commitment,
		Name:       landed.Name(),
		Padlock:    landed.Padlock(),
		Hints:      []string{"https://landing.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if departed.Voice != successor || len(departed.Peers) != 1 {
		t.Fatalf("the departure is %#v", departed)
	}
	// The relations went with the cargo, so the old door can spend nothing on
	// the being's behalf.
	if _, _, err := origin.Ask(warden.Reach{
		Far: peer.Name(), Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); err == nil {
		t.Fatal("the old door still holds a voice of the being's")
	}

	word, err := origin.News(warden.Tell{
		Peer:        departed.Peers[0],
		Voice:       departed.Voice,
		VoiceSecret: departed.VoiceSecret,
		Word:        departed.Word,
		Seq:         1,
		Allowance:   envelope.Allowance{Time: 5000, Hops: 8},
		Hints:       []string{"https://departing.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := peer.Arrive(word, nil)
	if data == nil {
		t.Fatal("the peer met the news it is owed with silence")
	}
	if data == nil {
		t.Fatal("the news was not answered at all")
	}

	// Believed news rewrites the row entire, so the peer now stands at the
	// house the being moved to and reaches it by the successor's name.
	name, held, padlock, hints, ok := peer.RelationAt(landed.Name())
	if !ok || name != landed.Name() || padlock != landed.Padlock() {
		t.Fatalf("the relation did not follow the being: %x %v", name, ok)
	}
	if held != inv.Commitment {
		t.Fatal("the house's own commitment was overwritten by a being's")
	}
	if len(hints) != 1 || hints[0] != "https://landing.example" {
		t.Fatalf("the roads did not travel: %v", hints)
	}
	if _, _, _, _, ok := peer.RelationAt(origin.Name()); ok {
		t.Fatal("the peer still stands at the door the being left")
	}

	// A peer that never spoke is reached by the only means left: it asks, and
	// the old door tells it the being has moved.
	if _, err := origin.News(warden.Tell{
		Peer:      warden.Peer{Voice: departed.Peers[0].Voice},
		Voice:     departed.Voice,
		Word:      departed.Word,
		Seq:       1,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); err == nil {
		t.Fatal("news left for a peer that named no way back")
	}
}

// TestPackCarriesTheStandingsAtTheBeingThatMoves holds the other half: the
// inbound rows travel so its peers keep their standing at it, and only the
// being that moves travels in a row — what the voice reaches here besides it
// is this door's affair.
func TestPackCarriesTheStandingsAtTheBeingThatMoves(t *testing.T) {
	g := stand(t)
	second, _, err := g.w.Hold(&other{}, warden.Holding{
		Blueprint: "Other\n  f() bool\n",
		Keys:      warden.Keys{Secret: secret("second"), HeirSecret: secret("secondHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two calls out of order, so the row has a mark and a window under it — the
	// replay record travels whole or every number already spent would come
	// round again at the new door, and a mark alone would either kill a caller
	// with asks in flight or reopen what was spent.
	g.rotate(1)
	s := g.say(g.inv.Heir, 3)
	g.answer(g.judge(g.inv.HeirSecret, s))
	if err := g.w.Widen(g.inv.Heir, second); err != nil {
		t.Fatal(err)
	}

	cargo, err := g.w.Pack(g.being, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cargo.Standings) != 1 {
		t.Fatalf("the cargo carries %d standings, want 1", len(cargo.Standings))
	}
	row := cargo.Standings[0]
	if row.Voice != g.inv.Heir {
		t.Fatal("the standing does not name the voice that holds it")
	}
	if row.Mark != 3 {
		t.Fatalf("the mark travelled as %d, want 3", row.Mark)
	}
	// The numbers below the mark already honoured, and only those: the mark is
	// spent by definition and travels as the mark. Two is not here, because two
	// never arrived — and that is exactly the fact the new door needs.
	if len(row.Spent) != 1 || row.Spent[0] != 1 {
		t.Fatalf("the window travelled as %v, want [1]", row.Spent)
	}
	// Only the being that moves, and under the name the first rotation gives
	// it: a cargo is packed under the committed heir, because the second of
	// migration's two rotations succeeds that name and not the one the being
	// wore here.
	heir := arithmetic.SigningKey(secret("beingHeir"))
	if len(row.Beings) != 1 || row.Beings[0] != heir {
		t.Fatalf("the standing carries %d beings, want only the one that moves", len(row.Beings))
	}
	if cargo.Being != heir {
		t.Fatal("the cargo is packed under the name the being wore here, not the one it takes")
	}
	if cargo.Digest != arithmetic.Hash([]byte(todoText)) {
		t.Fatal("the cargo does not name the being's class")
	}
	if _, err := g.w.Pack([32]byte{9}, nil); err == nil {
		t.Fatal("a warden packed a being it does not hold")
	}
}

// TestAMigratedRelationCanStillRotate holds the voice's keys, plural. A being
// that has already rotated once at a far door holds a standing whose next
// rotation needs the heir it committed there — a key the far door knows only
// by its hash. Carry the voice alone and the being can act once and never
// rotate again, and the heir stays behind at the origin, which would leave the
// old warden holding the one key that can take the standing over. So the heir
// travels, and the origin's copy dies with everything else it held.
func TestAMigratedRelationCanStillRotate(t *testing.T) {
	g := stand(t) // the destination, and the ordinary gate a receive spends
	third := house(t, "far")
	origin := house(t, "origin")

	room, _, err := third.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("far/room"), HeirSecret: secret("far/roomHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := third.GrantAs(room,
		warden.Keys{Secret: secret("far/voice"), HeirSecret: secret("far/voiceHeir")},
		third.Padlock(), []string{"https://far.example"})
	if err != nil {
		t.Fatal(err)
	}

	traveller, _, err := origin.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("origin/being"), HeirSecret: secret("origin/beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	origin.Stand(traveller, inv, inv.HeirSecret)

	// One rotation at the far door before the move. From here the far door
	// holds a commitment to a key nobody has spent yet, and only this ground
	// has its secret.
	first := secret("origin/firstHeir")
	message, _, err := origin.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &first,
	})
	if err != nil {
		t.Fatal(err)
	}
	if third.Arrive(message, nil) == nil {
		t.Fatal("the far door refused the first rotation")
	}

	cargo, err := origin.Pack(traveller, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cargo.Relations) != 1 {
		t.Fatalf("the cargo carries %d relations, want 1", len(cargo.Relations))
	}
	row := cargo.Relations[0]
	if row.HeirSecret != first || row.Heir != arithmetic.SigningKey(first) {
		t.Fatal("the heir the being committed at the far door did not travel")
	}
	if row.Seq != 1 {
		t.Fatalf("the count kept against that far door travelled as %d, want 1", row.Seq)
	}

	// The origin lets the being go, and its relations go with it: the copy of
	// that heir must not stay behind.
	origin.Release(traveller)
	if _, _, err := origin.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); err == nil {
		t.Fatal("the origin still holds a relation it handed over")
	}

	packed, err := warden.EncodeCargo(cargo)
	if err != nil {
		t.Fatal(err)
	}
	g.rotate(1)
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: packed}
	g.answer(g.judge(g.inv.HeirSecret, s))

	// And now the second rotation, which the old shape could not reach: the
	// being spends the heir it inherited, commits to one nobody has seen, and
	// the far door answers.
	next := secret("origin/secondHeir")
	message, seq, err := g.w.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("the rotation spent %d, want 1 — a rotation starts the count fresh", seq)
	}
	reply := third.Arrive(message, nil)
	if reply == nil {
		t.Fatal("the far door refused the arrived being's rotation")
	}
	answer, err := g.w.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != third.Name() || answer.Seq != seq {
		t.Fatalf("the answer is %#v", answer)
	}

	// The standing really changed hands: the voice that held it before the
	// move is now a stranger at that door, and a stranger reaches nothing but
	// the house's own public being.
	stale, err := arithmetic.SealingKey(secret("origin/stalePadlock"))
	if err != nil {
		t.Fatal(err)
	}
	dead, err := envelope.SealSay(secret("origin/ephemeral3"), third.Padlock(), inv.HeirSecret, envelope.Say{
		Voice:     inv.Heir,
		Recipient: third.Name(),
		Seq:       9,
		Padlock:   stale,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Being:     &room,
		Method:    &envelope.Method{Name: "count", Args: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if reply := third.Arrive(dead, nil); reply != nil {
		t.Fatal("the voice the being held before it moved still stands at the far door")
	}

	// And it can rotate again after that, because the row kept the new heir
	// exactly as the origin's did.
	third2 := secret("origin/thirdHeir")
	message, _, err = g.w.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &third2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if third.Arrive(message, nil) == nil {
		t.Fatal("the far door refused the rotation after the migrated one")
	}
}

// TestAHintIsCarriedByteForByte holds Article III's plainest rule about a
// hint: Quo never reads one and never rewrites one. A hint is compared,
// republished as news and stored in a row, so two spellings of one road would
// be two roads — which means the bytes that were granted are the bytes that
// come back.
func TestAHintIsCarriedByteForByte(t *testing.T) {
	g := stand(t)
	// Spellings a kit might be tempted to tidy: a case the URL scheme does not
	// care about, a leading zero, a trailing slash, a declared cap.
	hints := []string{
		"HTTPS://One.Example:00443/",
		"tcp://[2001:db8::1]:9000?cap=016384",
		"https://two.example",
	}

	inv, err := g.w.GrantAs(g.being,
		warden.Keys{Secret: secret("hintVoice"), HeirSecret: secret("hintHeir")},
		g.w.Padlock(), hints)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inv.Hints, hints) {
		t.Fatalf("the invitation carries %q", inv.Hints)
	}
	if !reflect.DeepEqual(g.w.Card(hints).Hints, hints) {
		t.Fatal("a card rewrote the roads it publishes")
	}

	// And a row keeps what it was handed, so what a peer republishes is what it
	// was told.
	guest := house(t, "hintGuest")
	guest.Stand(guest.Self(), inv, inv.HeirSecret)
	_, _, _, kept, ok := guest.RelationAt(inv.Warden)
	if !ok || !reflect.DeepEqual(kept, hints) {
		t.Fatalf("the row keeps %q", kept)
	}
}

// TestAcceptSpendsTheInvitationWhole holds the helper the table ruled every kit
// offers: an invitation is spent, not held. Whoever minted the voice has seen
// its keys and its heirs, so it takes two rotate-and-asks — the invitation's
// heir takes the standing and commits to a voice the granter never saw, then
// that voice commits to a fresh heir and carries the caller's own ask.
func TestAcceptSpendsTheInvitationWhole(t *testing.T) {
	delivery := warden.NewMemory()
	g := standDelivered(t, delivery)
	delivery.Attach("mem://whole", g.w)
	g.w.Publish("mem://whole")
	inv, err := g.w.GrantAs(g.being, warden.Keys{
		Secret: secret("whole/voice"), HeirSecret: secret("whole/voiceHeir"),
	}, g.w.Padlock(), g.w.Hints())
	if err != nil {
		t.Fatal(err)
	}

	guest := housed(t, "acceptor", delivery)
	handle, err := sole(guest.Accept(ctx(), inv, warden.Accepting{Label: "there"}))
	if err != nil {
		t.Fatalf("the invitation was not accepted: %v", err)
	}
	// What comes back is what a being calls: the one being the standing opens,
	// answering the field its blueprint declares.
	if handle.Being() != g.being {
		t.Fatal("the handle reaches a being the standing does not open")
	}
	if v, ok := handle.Call(ctx(), "add", "milk"); !ok || v.(string) != "milk" {
		t.Fatalf("the being answered %v %v", v, ok)
	}

	// Every key the granter ever held for this standing is dead: the voice it
	// minted and the heir it handed out both stand nowhere now, which drops
	// them to the stranger's case.
	for _, dead := range [][32]byte{secret("whole/voice"), inv.HeirSecret} {
		s := g.say(arithmetic.SigningKey(dead), 7)
		s.Being = &g.being
		s.Method = &envelope.Method{Name: "count", Args: []byte{}}
		// Each signs with its own secret, so what refuses it is the record
		// rather than the signature.
		g.silent(g.judge(dead, s))
	}

	// And the standing goes on being spent: the heir the accept committed to
	// rotates in its turn, and starts the far door's count over.
	third := secret("acceptor/third")
	message, seq, err := guest.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &third,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("the rotation spent %d, want 1", seq)
	}
	if g.w.Arrive(message, nil) == nil {
		t.Fatal("the door refused the rotation after the accept")
	}
}

// TestACopyOfTheInvitationCanNoLongerTakeTheStanding holds why the second
// rotation is not optional: until the holder stands on a key it generated
// itself, whoever minted the invitation — or anyone holding a copy — can still
// take the standing at that door.
func TestACopyOfTheInvitationCanNoLongerTakeTheStanding(t *testing.T) {
	delivery := warden.NewMemory()
	g := standDelivered(t, delivery)
	delivery.Attach("mem://copy", g.w)
	g.w.Publish("mem://copy")
	inv, err := g.w.GrantAs(g.being, warden.Keys{
		Secret: secret("copy/voice"), HeirSecret: secret("copy/voiceHeir"),
	}, g.w.Padlock(), g.w.Hints())
	if err != nil {
		t.Fatal(err)
	}
	guest := housed(t, "acceptor", delivery)
	if _, err := guest.Accept(ctx(), inv, warden.Accepting{Label: "there"}); err != nil {
		t.Fatal(err)
	}

	// Somebody else holding the same invitation replays the holder's first act.
	thief := house(t, "thief")
	thief.Stand(thief.Self(), inv, inv.HeirSecret)
	mine := secret("thief/heir")
	message, _, err := thief.Ask(warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The thief's voice is found nowhere, so it is answered as any stranger is
	// — the commitment it carries is ignored rather than refused. What matters
	// is that it takes nothing: the standing stayed where the accept left it.
	before := g.w.Standings(g.being)
	if g.w.Arrive(message, nil) == nil {
		t.Fatal("a stranger carrying a commitment met silence")
	}
	after := g.w.Standings(g.being)
	if len(after) != len(before) {
		t.Fatal("a copy of a spent invitation took the standing")
	}
	for at := range before {
		if before[at] != after[at] {
			t.Fatal("a copy of a spent invitation moved the standing")
		}
	}
}

// TestAPeerLearnsTheNewHouseFromTheDestinationItself walks a whole migration
// with a real peer at both ends, which is the only way the destination's half
// is proved: everything up to the cargo landing can be right while the new
// house is unable to say a word about the being it just took in.
//
// Migration is one message sent twice (Article XIV). The origin sends the
// first, signed by the being's committed heir. The second is signed by the key
// the destination generated and the origin never saw, and it can only come
// from the new house. Without it a peer's only road to the being's new home is
// asking the door it left, and no house should be the only way to find a
// house.
func TestAPeerLearnsTheNewHouseFromTheDestinationItself(t *testing.T) {
	g := stand(t) // the destination, and the ordinary gate a receive spends
	origin := house(t, "whole/origin")
	peer := house(t, "whole/peer")

	traveller, _, err := origin.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("whole/being"), HeirSecret: secret("whole/beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := origin.GrantAs(traveller,
		warden.Keys{Secret: secret("whole/voice"), HeirSecret: secret("whole/voiceHeir")},
		origin.Padlock(), []string{"https://origin.example"})
	if err != nil {
		t.Fatal(err)
	}
	peer.Stand(peer.Self(), inv, inv.HeirSecret)

	// The peer speaks once, which is how the origin learns the way back to it
	// and how the standing changes hands. Both travel in the cargo.
	next := secret("whole/peerHeir")
	message, _, err := peer.Ask(warden.Reach{
		Far:       origin.Name(),
		Being:     &traveller,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
		Hints:     []string{"https://peer.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if origin.Arrive(message, nil) == nil {
		t.Fatal("the origin refused the peer")
	}
	// The commitment a describe hands over, without which the peer holds no
	// material to believe this being's succession.
	committed := arithmetic.SigningKey(secret("whole/beingHeir"))
	if err := peer.Learn(origin.Name(), traveller, arithmetic.Commit(origin.Name(), committed)); err != nil {
		t.Fatal(err)
	}

	// The cargo is packed under the name the first rotation gives the being,
	// so the second rotation succeeds the name the peer will hold by then.
	cargo, err := origin.Pack(traveller, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if cargo.Being != committed {
		t.Fatal("the cargo is not packed under the name the first rotation gives the being")
	}
	packed, err := warden.EncodeCargo(cargo)
	if err != nil {
		t.Fatal(err)
	}
	g.rotate(1)
	s := g.say(g.inv.Heir, 2)
	s.Being = g.own()
	s.Method = &envelope.Method{Name: warden.FieldReceive, Args: packed}
	answered := g.answer(g.judge(g.inv.HeirSecret, s))
	var commitment [32]byte
	copy(commitment[:], answered)

	// The destination's half. The word is composed by the kit and not by the
	// host: a house that took a cargo in and then had to invent the
	// announcement would invent a different one at every ground.
	landed, ok := g.w.Landed([]string{"https://landing.example"})
	if !ok {
		t.Fatal("the destination has nothing to say about the being it just took in")
	}
	arrivedAs := arithmetic.SigningKey(secret("receiveBeing"))
	if landed.Being != arrivedAs || landed.BeingSecret != secret("receiveBeing") {
		t.Fatal("the destination does not hand back the key it generated")
	}
	if landed.Word.Being == nil || *landed.Word.Being != cargo.Being {
		t.Fatal("the second word does not succeed the name the first one moved to")
	}
	if landed.Word.Successor == nil || *landed.Word.Successor != arrivedAs {
		t.Fatal("the second word does not name the key the origin never saw")
	}
	if landed.Word.Commitment == nil || *landed.Word.Commitment != arithmetic.Commit(g.w.Name(), arithmetic.SigningKey(secret("receiveHeir"))) {
		t.Fatal("the second word carries no material for the succession after it")
	}
	if len(landed.Peers) != 1 || landed.Peers[0].Padlock == nil || *landed.Peers[0].Padlock != peer.Padlock() {
		t.Fatalf("the peers that arrived with the standings are %#v", landed.Peers)
	}

	// The origin's half, carrying as its next commitment the one `receive`
	// answered — the one fact it cannot invent.
	departed, err := origin.Depart(traveller, warden.Departing{
		HeirSecret: secret("whole/beingHeir"),
		Commitment: commitment,
		Name:       g.w.Name(),
		Padlock:    g.w.Padlock(),
		Hints:      []string{"https://landing.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := origin.News(warden.Tell{
		Peer: departed.Peers[0], Voice: departed.Voice, VoiceSecret: departed.VoiceSecret,
		Word: departed.Word, Seq: 1, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	if peer.Arrive(first, nil) == nil {
		t.Fatal("the peer met the first news with silence")
	}

	// And the second, from the new house itself, signed by the key it
	// generated. A being's succession starts the news mark fresh, so it counts
	// from one again.
	second, err := g.w.News(warden.Tell{
		Peer: landed.Peers[0], Voice: landed.Being, VoiceSecret: landed.BeingSecret,
		Word: landed.Word, Seq: 1, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Hints: []string{"https://landing.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if peer.Arrive(second, nil) == nil {
		t.Fatal("the peer met the second news with silence")
	}

	// Believed news rewrites the row entire, so the peer now stands at the new
	// house and reaches the being by the name that house minted.
	name, held, padlock, hints, ok := peer.RelationAt(g.w.Name())
	if !ok || name != g.w.Name() || padlock != g.w.Padlock() {
		t.Fatalf("the relation did not follow the being: %x %v", name, ok)
	}
	if held != inv.Commitment {
		t.Fatal("the house's own commitment was overwritten by a being's")
	}
	if len(hints) != 1 || hints[0] != "https://landing.example" {
		t.Fatalf("the roads did not travel: %v", hints)
	}

	// And the destination points for the name the being used to wear. A peer
	// behind the news asks the door it knows; a new house that could not point
	// for the old name would make the old door the only way to find the being,
	// which is the whole of what Article XIII's pointer exists to avoid.
	arg, err := wire.Encode(warden.Own, keyType(), cargo.Being)
	if err != nil {
		t.Fatal(err)
	}
	at := g.w.Name()
	message, _, err = peer.Ask(warden.Reach{
		Far:       g.w.Name(),
		Being:     &at,
		Method:    &envelope.Method{Name: warden.FieldMoved, Args: arg},
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := g.w.Arrive(message, nil)
	if reply == nil {
		t.Fatal("the destination met a holder's `moved` with silence")
	}
	heard, err := peer.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(heard.Data) == 0 || heard.Data[0] != 1 {
		t.Fatalf("`moved` answered %x where the word was due", heard.Data)
	}
	word, err := warden.DecodeWord(heard.Data[1:])
	if err != nil {
		t.Fatal(err)
	}
	// The word a peer hears and the word a peer gets by asking are the
	// identical bytes, roads included.
	if !reflect.DeepEqual(word, landed.Word) {
		t.Fatalf("the published word is %#v, want %#v", word, landed.Word)
	}

	// A stranger gets nothing: the pointer is owed to a holder who reached the
	// being before, and never to whoever guessed a name.
	stranger := g.say(arithmetic.SigningKey(secret("whole/passerby")), 1)
	stranger.Being = g.own()
	stranger.Method = &envelope.Method{Name: warden.FieldMoved, Args: arg}
	g.silent(g.judge(secret("whole/passerby"), stranger))
}
