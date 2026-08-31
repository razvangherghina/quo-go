package carriage_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
)

// A door in the middle of a chain, over the common carriage and nothing else.
// A client asks an agency; the agency, doing its work, reaches a subcontractor
// at a third door — and the caller there is the agency's voice, judged by the
// agency's standing, never the client's. Authority does not travel along a
// walk.
//
// What the chain proves that no vector can: the middle door hands onward less
// than it received.

const agencyText = "Agency\n  total() int\n"

// agency is a being that acts. Its author handed it a warden on purpose, and
// the one thing it takes from each call is the leash, because the allowance
// belongs to the message rather than to the being.
type agency struct {
	w       *warden.Warden
	far     [32]byte
	target  [32]byte
	next    *[32]byte
	hints   []string
	opens   [32]byte
	onward  envelope.Allowance // what it last handed to the far door
	arrived envelope.Allowance // and what arrived at it
	clock   *tick
	dwell   int64 // milliseconds of work, on the door's own clock
}

func (a *agency) Invoke(call warden.Call) ([]byte, error) {
	if call.Method != "total" {
		return nil, errors.New("the blueprint declares no such field")
	}
	a.arrived = call.Leash.Received()
	// The work this door does on the client's behalf. The dwell is the
	// difference between when the message arrived and when it is handed
	// onward, so it is spent here, between the two readings.
	a.clock.step(a.dwell)

	leash := call.Leash
	message, seq, err := a.w.Ask(secret("agency/ephemeral"), warden.Reach{
		Far:      a.far,
		Being:    &a.target,
		Method:   &envelope.Method{Name: "count", Args: []byte{}},
		Leash:    &leash,
		NextHeir: a.next,
	})
	if err != nil {
		return nil, err
	}
	a.next = nil
	// What actually crossed, read off the payload this being just sealed.
	sent, err := envelope.OpenSay(secret("subcontractor/padlock"), message)
	if err != nil {
		return nil, err
	}
	a.onward = sent.Allowance

	reply, err := carriage.Caller{}.Send(a.hints, message)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		// Silence from the far door is silence from this one: a warden never
		// narrates what happened behind it.
		return nil, errors.New("the far door said nothing")
	}
	answer, err := a.w.Hear(a.opens, reply)
	if err != nil {
		return nil, err
	}
	if answer.Seq != seq {
		return nil, errors.New("the answer names another ask")
	}
	return answer.Data, nil
}

// TestADoorStandsInTheMiddleOfAChain drives client → agency → subcontractor
// over two real POSTs, and holds that the middle door handed onward one fewer
// hop and no more time than arrived.
func TestADoorStandsInTheMiddleOfAChain(t *testing.T) {
	clock := &tick{}

	// The far door, holding the being that does the work.
	sub := stand(t, "subcontractor")
	target, err := sub.Hold(todoText, &todo{items: []string{"one", "two"}},
		warden.Keys{Secret: secret("sub/being"), HeirSecret: secret("sub/beingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	subDoor := serve(t, sub, "subcontractor")
	toAgency, err := sub.Grant(target,
		warden.Keys{Secret: secret("sub/voice"), HeirSecret: secret("sub/voiceHeir")},
		sub.Padlock(), []string{subDoor.URL})
	if err != nil {
		t.Fatal(err)
	}

	// The middle door, on a clock the bench holds, so its dwell is a fact and
	// not a measurement of the machine this runs on.
	mid := standAt(t, "agency", clock.read)
	a := &agency{
		w: mid, far: toAgency.Warden, target: target, hints: toAgency.Hints,
		opens: secret("agency/padlock"), clock: clock, dwell: 40,
	}
	next := secret("agency/nextHeir")
	a.next = &next
	being, err := mid.Hold(agencyText, a, warden.Keys{Secret: secret("agency/being"), HeirSecret: secret("agency/beingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	mid.Stand(being, toAgency, toAgency.HeirSecret)
	midDoor := serve(t, mid, "agency")

	toClient, err := mid.Grant(being,
		warden.Keys{Secret: secret("agency/voice"), HeirSecret: secret("agency/voiceHeir")},
		mid.Padlock(), []string{midDoor.URL})
	if err != nil {
		t.Fatal(err)
	}

	// The client, which knows nothing of the third door and holds nothing
	// there.
	client := stand(t, "client")
	client.Stand(client.Self(), toClient, toClient.HeirSecret)
	mine := secret("client/heir")
	message, seq, err := client.Ask(secret("client/ephemeral"), warden.Reach{
		Far:       toClient.Warden,
		Being:     &being,
		Method:    &envelope.Method{Name: "total", Args: []byte{}},
		Allowance: envelope.Allowance{Time: 5000, Hops: 4},
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}

	reply, err := carriage.Caller{}.Send(toClient.Hints, message)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil {
		t.Fatal("the agency answered silence")
	}
	answer, err := client.Hear(client.PadlockSecret(), reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Seq != seq {
		t.Fatalf("the answer names ask %d, not %d", answer.Seq, seq)
	}
	// The work happened at the third door and came back through the second.
	if n := binary.BigEndian.Uint64(answer.Data); n != 2 {
		t.Fatalf("the far being answered %d, want 2", n)
	}

	if a.arrived != (envelope.Allowance{Time: 5000, Hops: 4}) {
		t.Fatalf("the being was handed %v, not what the client sent", a.arrived)
	}
	if a.onward.Hops != 3 {
		t.Fatalf("four hops arrived at the middle door and %d went onward", a.onward.Hops)
	}
	if a.onward.Time != 4960 {
		t.Fatalf("the middle door dwelt forty milliseconds and handed on %d of 5000", a.onward.Time)
	}
}
