package warden_test

import (
	"reflect"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
)

// The inward side of the record — granting, amending, releasing — and the
// outward side of a call — composing one, counting it, and rotating with it.
// Every case is asserted from the law's own words; none of it produces bytes
// the corpus could measure.

// estate describes at that number and hands back the classes the holder sees.
func (g *ground) estate(seq int64) []warden.Class {
	g.t.Helper()
	return mustEstate(g.t, g.answer(g.judge(g.inv.HeirSecret, g.say(g.inv.Heir, seq)))).Classes
}

// house stands a second ground up, so a call has somewhere to come from.
func house(t *testing.T, label string) *warden.Warden {
	t.Helper()
	name := secret(label + "/name")
	w, err := warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(secret(label+"/wardenHeir"))),
		PadlockSecret:  secret(label + "/padlock"),
		Limit:          1 << 20,
		Clock:          (&tick{}).read,
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
	second, err := g.w.Hold("Other\n  f() bool\n", &todo{}, warden.Keys{Secret: secret("second"), HeirSecret: secret("secondHeir")})
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
	if _, err := g.w.Grant(g.being, warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")}, g.w.Padlock(), nil); err == nil {
		t.Fatal("one voice was granted twice")
	}
}

// TestGrantRefusesABeingTheWardenDoesNotHold holds that a warden grants only
// at what it keeps.
func TestGrantRefusesABeingTheWardenDoesNotHold(t *testing.T) {
	g := stand(t)
	if _, err := g.w.Grant([32]byte{9}, warden.Keys{Secret: secret("v2"), HeirSecret: secret("v2h")}, g.w.Padlock(), nil); err == nil {
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
		if _, _, err := caller.Ask(secret("askEphemeral"), warden.Reach{Far: g.inv.Warden, Allowance: leash}); err == nil {
			t.Fatalf("a call with %#v left this ground", leash)
		}
	}
	if _, _, err := caller.Ask(secret("askEphemeral"), warden.Reach{
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
	if _, _, err := caller.Ask(secret("askEphemeral"), warden.Reach{
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
	if _, seq, err := caller.Ask(secret("e1"), rotate); err != nil || seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d (%v), want 1", seq, err)
	}
	for want := int64(2); want <= 4; want++ {
		_, seq, err := caller.Ask(secret("e1"), reach)
		if err != nil || seq != want {
			t.Fatalf("spent %d (%v), want %d", seq, err, want)
		}
	}
	// A rotation starts the count fresh, because the old key died with it.
	next := secret("callerHeir2")
	rotate.NextHeir = &next
	if _, seq, err := caller.Ask(secret("e1"), rotate); err != nil || seq != 1 {
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
	message, _, err := caller.Ask(secret("askEphemeral"), warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err := envelope.OpenSay(g.w.PadlockSecret(), message)
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
	message, _, err = caller.Ask(secret("askEphemeral"), warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err = envelope.OpenSay(g.w.PadlockSecret(), message)
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

	message, _, err := caller.Ask(secret("askEphemeral"), warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err := envelope.OpenSay(g.w.PadlockSecret(), message)
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
	alone, err := arithmetic.SealingKey(secret("perRelation"))
	if err != nil {
		t.Fatal(err)
	}
	message, _, err = caller.Ask(secret("askEphemeral"), warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Padlock:   alone,
	})
	if err != nil {
		t.Fatal(err)
	}
	say, err = envelope.OpenSay(g.w.PadlockSecret(), message)
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

	alone, err := arithmetic.SealingKey(secret("perRelation"))
	if err != nil {
		t.Fatal(err)
	}
	mine := secret("callerHeir")
	message, seq, err := caller.Ask(secret("askEphemeral"), warden.Reach{
		Far:       g.inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Padlock:   alone,
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := g.w.Judge(warden.Draws{Ephemeral: secret("answerEphemeral"), Heir: secret("receiveHeir")}, message)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := caller.Hear(secret("perRelation"), reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != g.w.Name() || answer.Seq != seq {
		t.Fatalf("the answer is %#v", answer)
	}
	if _, err := caller.Hear(caller.PadlockSecret(), reply); err == nil {
		t.Fatal("the answer opened under a padlock the payload never named")
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
	room, err := third.Hold(todoText, &todo{}, warden.Keys{Secret: secret("third/room"), HeirSecret: secret("third/roomHeir")})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := third.Grant(room,
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
	if _, _, err := g.w.Ask(secret("askEphemeral"), warden.Reach{
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
	message, seq, err := g.w.Ask(secret("askEphemeral2"), warden.Reach{
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
	reply, err := third.Judge(warden.Draws{Ephemeral: secret("third/answerEphemeral")}, message)
	if err != nil {
		t.Fatalf("the third door refused the arrived being: %v", err)
	}
	answer, err := g.w.Hear(g.w.PadlockSecret(), reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != third.Name() || answer.Seq != seq {
		t.Fatalf("the answer is %#v", answer)
	}

	// Pack reads the same row back off the record, so a being that moved once
	// can move again.
	again, err := g.w.Pack(arriving, []byte("state"))
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

// TestPackCarriesTheStandingsAtTheBeingThatMoves holds the other half: the
// inbound rows travel so its peers keep their standing at it, and only the
// being that moves travels in a row — what the voice reaches here besides it
// is this door's affair.
func TestPackCarriesTheStandingsAtTheBeingThatMoves(t *testing.T) {
	g := stand(t)
	second, err := g.w.Hold("Other\n  f() bool\n", &todo{}, warden.Keys{Secret: secret("second"), HeirSecret: secret("secondHeir")})
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
	if len(row.Beings) != 1 || row.Beings[0] != g.being {
		t.Fatalf("the standing carries %d beings, want only the one that moves", len(row.Beings))
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

	room, err := third.Hold(todoText, &todo{}, warden.Keys{Secret: secret("far/room"), HeirSecret: secret("far/roomHeir")})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := third.Grant(room,
		warden.Keys{Secret: secret("far/voice"), HeirSecret: secret("far/voiceHeir")},
		third.Padlock(), []string{"https://far.example"})
	if err != nil {
		t.Fatal(err)
	}

	traveller, err := origin.Hold(todoText, &todo{}, warden.Keys{Secret: secret("origin/being"), HeirSecret: secret("origin/beingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	origin.Stand(traveller, inv, inv.HeirSecret)

	// One rotation at the far door before the move. From here the far door
	// holds a commitment to a key nobody has spent yet, and only this ground
	// has its secret.
	first := secret("origin/firstHeir")
	message, _, err := origin.Ask(secret("origin/ephemeral"), warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &first,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.Judge(warden.Draws{Ephemeral: secret("far/answerEphemeral")}, message); err != nil {
		t.Fatalf("the far door refused the first rotation: %v", err)
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
	if _, _, err := origin.Ask(secret("origin/ephemeral2"), warden.Reach{
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
	message, seq, err := g.w.Ask(secret("destination/ephemeral"), warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &next,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("the rotation spent %d, want 1 — a rotation starts the count fresh", seq)
	}
	reply, err := third.Judge(warden.Draws{Ephemeral: secret("far/answerEphemeral2")}, message)
	if err != nil {
		t.Fatalf("the far door refused the arrived being's rotation: %v", err)
	}
	answer, err := g.w.Hear(g.w.PadlockSecret(), reply)
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
	if reply, err := third.Judge(warden.Draws{Ephemeral: secret("far/answerEphemeral4")}, dead); err == nil || reply != nil {
		t.Fatal("the voice the being held before it moved still stands at the far door")
	}

	// And it can rotate again after that, because the row kept the new heir
	// exactly as the origin's did.
	third2 := secret("origin/thirdHeir")
	message, _, err = g.w.Ask(secret("destination/ephemeral2"), warden.Reach{
		Far: inv.Warden, Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &third2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.Judge(warden.Draws{Ephemeral: secret("far/answerEphemeral3")}, message); err != nil {
		t.Fatalf("the far door refused the rotation after the migrated one: %v", err)
	}
}
