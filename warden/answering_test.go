package warden_test

import (
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
)

// The caller's own half, which is the half a door's bench never exercises: the
// relation it writes, the numbers it chooses, the asks it keeps a record of,
// and the shorter road Article XII gives an answer at the caller's end. Every
// case here is a refusal a green door would never have shown.

// calling stands a caller up against g, holding g's invitation.
func calling(t *testing.T, g *ground, label string) *warden.Warden {
	t.Helper()
	w := house(t, label)
	w.Stand(w.Self(), g.inv, g.inv.HeirSecret)
	return w
}

// reach is the ordinary ask down a relation, with a leash that leaves room.
func reach(far [32]byte) warden.Reach {
	return warden.Reach{Far: far, Allowance: envelope.Allowance{Time: 5000, Hops: 8}}
}

// exchange composes one ask, has the door judge it, and hands the caller its
// own reply to judge.
func exchange(t *testing.T, g *ground, caller *warden.Warden, r warden.Reach, e string) (envelope.Answer, error) {
	t.Helper()
	message, _, err := caller.Ask(secret(e), r)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := g.w.Judge(warden.Draws{Ephemeral: secret(e + "/answer")}, message)
	if err != nil {
		t.Fatalf("the door met the call with silence: %v", err)
	}
	return caller.Hear(caller.PadlockSecret(), reply)
}

// TestAHeldRelationKeepsTheHeirTheInvitationCarried holds the fifth of the five
// things Article VII says a holder holds. A rotation is signed by the heir and
// by nothing else, so a row that dropped the heir keypair would stand at a
// house it could never rotate at — and nothing would say so until the second
// rotation, which is the one no demo has ever made.
func TestAHeldRelationKeepsTheHeirTheInvitationCarried(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")

	// Two rotations, which is one more than any demo makes. The second is the
	// one that can only be signed by the key the first committed to.
	first := secret("caller/heir1")
	rotation := reach(g.inv.Warden)
	rotation.NextHeir = &first
	if _, err := exchange(t, g, caller, rotation, "e1"); err != nil {
		t.Fatalf("the first rotation was refused at the caller: %v", err)
	}

	second := secret("caller/heir2")
	rotation.NextHeir = &second
	if _, err := exchange(t, g, caller, rotation, "e2"); err != nil {
		t.Fatalf("the second rotation was refused at the caller: %v", err)
	}

	// And the standing is on the key the first rotation committed to, which is
	// what proves the second was signed by the heir rather than by the voice.
	holders := g.w.Standings(g.being)
	if len(holders) != 1 || holders[0] != arithmetic.SigningKey(first) {
		t.Fatalf("the standing stands on %x", holders)
	}
}

// TestARelationWithNoHeirCannotRotate is the same fact said as a refusal. A
// cargo that travelled without its heir arrives holding a standing nobody can
// take over, and the kit says so where it happens rather than signing with the
// voice and presenting a holder as its own heir.
func TestARelationWithNoHeirCannotRotate(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")
	stripped := g.inv
	stripped.HeirSecret = [32]byte{}
	caller.Stand(caller.Self(), stripped, g.inv.HeirSecret)

	mine := secret("caller/heir")
	r := reach(g.inv.Warden)
	r.NextHeir = &mine
	if _, _, err := caller.Ask(secret("e1"), r); err == nil {
		t.Fatal("a relation holding no heir rotated anyway")
	}
	// An ordinary ask still stands: what is missing is the heir, not the voice.
	if _, _, err := caller.Ask(secret("e2"), reach(g.inv.Warden)); err != nil {
		t.Fatalf("an ordinary ask was refused too: %v", err)
	}
}

// TestACargoCarriesTheHeirOrArrivesUnrotatable holds the same defect where it
// was invisible: Pack reads the heir off the row, so a row that never kept one
// packs a commitment to a key nobody holds.
func TestACargoCarriesTheHeirOrArrivesUnrotatable(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")
	being, err := caller.Hold(todoText, &todo{}, warden.Keys{Secret: secret("caller/being"), HeirSecret: secret("caller/beingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	// The relation is held by that being, so it travels when the being does.
	caller.Stand(being, g.inv, g.inv.HeirSecret)

	cargo, err := caller.Pack(being, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cargo.Relations) != 1 {
		t.Fatalf("the cargo carries %d relations", len(cargo.Relations))
	}
	if cargo.Relations[0].HeirSecret != g.inv.HeirSecret {
		t.Fatal("the cargo travelled without the heir the invitation carried")
	}
	if cargo.Relations[0].Heir != g.inv.Heir {
		t.Fatal("the cargo named an heir the destination could never spend")
	}
}

// TestACallerChoosesWhichNumberItOpensWith holds Article VIII's clause. A fresh
// mark is empty, so every number at or above one stands above it, and no door
// may require a first message to carry exactly one. A kit that always counted
// from one would be keeping a choice the law gives the caller.
func TestACallerChoosesWhichNumberItOpensWith(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")

	mine := secret("caller/heir")
	opening := int64(4_096)
	r := reach(g.inv.Warden)
	r.NextHeir = &mine
	r.Seq = &opening
	message, seq, err := caller.Ask(secret("e1"), r)
	if err != nil || seq != opening {
		t.Fatalf("the ask spent %d (%v), want %d", seq, err, opening)
	}
	reply, err := g.w.Judge(warden.Draws{Ephemeral: secret("e1/answer")}, message)
	if err != nil {
		t.Fatalf("the door refused an opening number above one: %v", err)
	}
	answer, err := caller.Hear(caller.PadlockSecret(), reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Seq != opening {
		t.Fatalf("the answer names ask %d", answer.Seq)
	}

	// And the row counts on from there, because per voice the number only
	// rises. A number the relation has already spent is refused here rather
	// than met with silence at the far door.
	spent := opening
	back := reach(g.inv.Warden)
	back.Seq = &spent
	if _, _, err := caller.Ask(secret("e2"), back); err == nil {
		t.Fatal("a number this relation had already spent went out again")
	}
	if _, next, err := caller.Ask(secret("e3"), reach(g.inv.Warden)); err != nil || next != opening+1 {
		t.Fatalf("the row counted on to %d (%v)", next, err)
	}
}

// TestAnAnswerFromADoorThisAskNeverWentTo holds the second of Article XII's two
// answer checks. The first — the signature verified against the warden the
// answer's own record carries — passes here, because the answer really is
// signed by the house that made it. It is the wrong house, and only the
// caller's own record says so.
func TestAnAnswerFromADoorThisAskNeverWentTo(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")

	// A second house the caller holds no relation with, granting the same
	// caller a standing so it can produce a well-signed answer at all.
	other := house(t, "other")
	room, err := other.Hold(todoText, &todo{}, warden.Keys{Secret: secret("other/room"), HeirSecret: secret("other/roomHeir")})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := other.Grant(room,
		warden.Keys{Secret: secret("other/voice"), HeirSecret: secret("other/voiceHeir")},
		other.Padlock(), []string{"https://other.example"})
	if err != nil {
		t.Fatal(err)
	}
	// A well-formed rotate-and-ask at that other house, sealed to the caller's
	// own padlock, so what comes back opens perfectly at the caller's end.
	elsewhere := house(t, "elsewhere")
	elsewhere.Stand(elsewhere.Self(), inv, inv.HeirSecret)
	mine := secret("elsewhere/heir")
	r := warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Padlock:   caller.Padlock(),
		NextHeir:  &mine,
	}
	message, _, err := elsewhere.Ask(secret("e1"), r)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := other.Judge(warden.Draws{Ephemeral: secret("e1/answer")}, message)
	if err != nil {
		t.Fatal(err)
	}

	// It unseals, it decodes, and its signature verifies against the warden the
	// record itself carries. It is still silence at this caller.
	if _, err := envelope.OpenAnswer(caller.PadlockSecret(), reply); err != nil {
		t.Fatalf("the answer is well-formed and well-signed: %v", err)
	}
	if _, err := caller.Hear(caller.PadlockSecret(), reply); err == nil {
		t.Fatal("an answer from a house this caller never asked was accepted")
	}
}

// TestAnAnswerNothingAwaitsIsSilence holds Article XII's fourth check. The
// answer is this door's own, correctly signed, correctly addressed — and it
// answers an ask that was never made, or one whose answer has already been
// heard. Either way the caller's record says nothing awaits it.
func TestAnAnswerNothingAwaitsIsSilence(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")

	mine := secret("caller/heir")
	r := reach(g.inv.Warden)
	r.NextHeir = &mine
	message, seq, err := caller.Ask(secret("e1"), r)
	if err != nil {
		t.Fatal(err)
	}
	if n := caller.Awaiting(g.inv.Warden); n != 1 {
		t.Fatalf("%d asks await an answer, want 1", n)
	}
	reply, err := g.w.Judge(warden.Draws{Ephemeral: secret("e1/answer")}, message)
	if err != nil {
		t.Fatal(err)
	}

	// Heard once, and the record is spent with it.
	answer, err := caller.Hear(caller.PadlockSecret(), reply)
	if err != nil || answer.Seq != seq {
		t.Fatalf("the answer was refused: %v", err)
	}
	if n := caller.Awaiting(g.inv.Warden); n != 0 {
		t.Fatalf("%d asks still await an answer", n)
	}
	// The very same bytes again are silence, because nothing awaits them.
	if _, err := caller.Hear(caller.PadlockSecret(), reply); err == nil {
		t.Fatal("an answer already heard was heard a second time")
	}
}

// TestTwoAsksWhoseAnswersCouldNotBeToldApart holds the clause Article XII gives
// the caller's own kit: it refuses to send the second. The shape that makes it
// real is a rotation, which starts the far door's mark fresh and so brings a
// number the caller is already awaiting round again.
func TestTwoAsksWhoseAnswersCouldNotBeToldApart(t *testing.T) {
	g := stand(t)
	caller := calling(t, g, "caller")

	first := secret("caller/heir1")
	rotation := reach(g.inv.Warden)
	rotation.NextHeir = &first
	if _, seq, err := caller.Ask(secret("e1"), rotation); err != nil || seq != 1 {
		t.Fatalf("the first rotation spent %d (%v)", seq, err)
	}

	// Number one is out and unanswered. A second rotation would open at one
	// too, and the two answers would name the same padlock, warden and seq.
	second := secret("caller/heir2")
	rotation.NextHeir = &second
	if _, _, err := caller.Ask(secret("e2"), rotation); err == nil {
		t.Fatal("two asks went out whose answers could not be told apart")
	}

	// Forgoing the first is the caller saying it has stopped waiting, and the
	// number is free to come round again.
	if !caller.Forgo(g.inv.Warden, 1, [32]byte{}) {
		t.Fatal("there was nothing to forgo")
	}
	if _, seq, err := caller.Ask(secret("e2"), rotation); err != nil || seq != 1 {
		t.Fatalf("the second rotation spent %d (%v)", seq, err)
	}
	// And forgoing what nothing awaits changes nothing.
	if caller.Forgo(g.inv.Warden, 99, [32]byte{}) {
		t.Fatal("an ask nobody made was forgone")
	}
}

// TestAcceptLeavesNothingAwaitingItWillNotHear holds the helper's own half of
// the same rule. Both of its rotate-and-asks open at one, and it hands the
// first answer back sealed rather than judging it — so it must stop awaiting
// that one, or its own second ask is the one the kit refuses to send.
func TestAcceptLeavesNothingAwaitingItWillNotHear(t *testing.T) {
	g := stand(t)
	caller := house(t, "caller")

	sent := 0
	accepted, err := caller.Accept(g.inv, warden.Accepting{
		Holder:      caller.Self(),
		VoiceSecret: secret("caller/voice"),
		HeirSecret:  secret("caller/heir"),
		Allowance:   envelope.Allowance{Time: 5000, Hops: 8},
		Ephemeral:   [2][32]byte{secret("e1"), secret("e2")},
		Send: func(message []byte) ([]byte, error) {
			sent++
			return g.w.Judge(warden.Draws{Ephemeral: secret("answer")}, message)
		},
	})
	if err != nil {
		t.Fatalf("accepting the invitation was refused: %v", err)
	}
	if sent != 2 {
		t.Fatalf("accept sent %d envelopes, want 2", sent)
	}
	// One ask is still out: the one carrying the caller's own call, which the
	// caller has the answer to and may judge.
	if n := caller.Awaiting(accepted.Far); n != 1 {
		t.Fatalf("%d asks await an answer after accept, want 1", n)
	}
	if _, err := caller.Hear(caller.PadlockSecret(), accepted.Answer); err != nil {
		t.Fatalf("the answer accept handed back was refused: %v", err)
	}
	if n := caller.Awaiting(accepted.Far); n != 0 {
		t.Fatalf("%d asks still await an answer", n)
	}
}
