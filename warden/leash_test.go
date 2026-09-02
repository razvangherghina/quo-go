package warden_test

import (
	"context"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
)

// The leash, and the being that spends it. A walk that crosses wardens is
// invisible to every one of them, so only something travelling with the walk
// can end it — and the constitution rules the arithmetic rather than leaving
// it to the implementer, because strangers must agree what the numbers mean.
//
// None of this produces bytes the corpus could measure: two kits can pass every
// vector and still hand onward different allowances.

const relayText = "Relay\n  pass() int\n"

// relay is a being that acts. It takes its warden the ordinary way any
// dependency is taken, by its author, on purpose — nothing is injected into it
// behind its back — and the one thing it cannot hold in advance is the
// allowance, because that belongs to the message.
type relay struct {
	warden.Attach
	w      *warden.Warden
	far    [32]byte
	target [32]byte
	next   *[32]byte // the fresh commitment its first call carries

	message []byte // what it last handed onward, still sealed
	err     error
	dwell   int64 // milliseconds it spends before reaching out
	clock   *tick
	greedy  bool // names a generous allowance of its own beside the leash
}

func (r *relay) Pass(ctx context.Context) (int64, error) {
	// The work this being does on the caller's behalf. The budget falls by it,
	// because the dwell is the difference between when the message arrived and
	// when it is handed onward.
	r.clock.step(r.dwell)

	leash := warden.Of(ctx).Leash
	reach := warden.Reach{
		Far:      r.far,
		Being:    &r.target,
		Method:   &envelope.Method{Name: "count", Args: []byte{}},
		Leash:    &leash,
		NextHeir: r.next,
	}
	if r.greedy {
		reach.Allowance = envelope.Allowance{Time: 1 << 30, Hops: 99}
	}
	message, seq, err := r.w.Ask(reach)
	r.next = nil
	r.message, r.err = message, err
	if err != nil {
		return 0, err
	}
	// Delivery is not Quo's, so nothing here carries the bytes. What this
	// being answers is the number it spent.
	return seq, nil
}

// door stands a ground up on a clock the bench holds.
func door(t *testing.T, label string, clock func() int64) *warden.Warden {
	t.Helper()
	name := secret(label + "/name")
	w, err := warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(secret(label+"/wardenHeir"))),
		PadlockSecret:  secret(label + "/padlock"),
		Limit:          1 << 20,
		Clock:          clock,
		Random:         fixed(label),
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// chain is a caller, a door holding a being that acts, and a far door that
// being stands at — the shape the law's "in a chain, each hop acts as
// itself" paragraph describes.
type chain struct {
	t      *testing.T
	middle *ground
	far    *warden.Warden
	relay  *relay
}

func link(t *testing.T, dwell int64) *chain {
	t.Helper()
	clockM, clockF := &tick{}, &tick{}
	middle := door(t, "middle", clockM.read)
	far := door(t, "far", clockF.read)

	target, _, err := far.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("far/being"), HeirSecret: secret("far/beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	invFar, err := far.GrantAs(target, warden.Keys{Secret: secret("far/voice"), HeirSecret: secret("far/voiceHeir")}, far.Padlock(), []string{"https://far.example"})
	if err != nil {
		t.Fatal(err)
	}

	next := secret("relay/nextHeir")
	r := &relay{w: middle, far: far.Name(), target: target, next: &next, dwell: dwell, clock: clockM}
	being, _, err := middle.Hold(r, warden.Holding{
		Blueprint: relayText,
		Keys:      warden.Keys{Secret: secret("middle/being"), HeirSecret: secret("middle/beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The being's standing at the far door: a relation this ground holds, and
	// the being that may spend it.
	middle.Stand(being, invFar, invFar.HeirSecret)

	returned, err := arithmetic.SealingKey(secret("caller/padlock"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := middle.GrantAs(being, warden.Keys{Secret: secret("middle/voice"), HeirSecret: secret("middle/voiceHeir")}, middle.Padlock(), nil)
	if err != nil {
		t.Fatal(err)
	}
	g := &ground{t: t, w: middle, clock: clockM, being: being, inv: inv, returned: returned, opens: secret("caller/padlock")}
	return &chain{t: t, middle: g, far: far, relay: r}
}

// pass sends one call to the being that acts, under the allowance given, and
// hands back what the middle door handed onward.
func (c *chain) pass(seq int64, a envelope.Allowance) envelope.Say {
	c.t.Helper()
	s := c.middle.say(c.middle.inv.Heir, seq)
	s.Being = &c.middle.being
	s.Method = &envelope.Method{Name: "pass", Args: []byte{}}
	s.Allowance = a
	if seq == 1 {
		next := arithmetic.Commit(c.middle.w.Name(), arithmetic.SigningKey(secret("caller/ownHeir")))
		s.Commitment = &next
	}
	c.middle.answer(c.middle.judge(c.middle.inv.HeirSecret, s))
	if c.relay.err != nil {
		c.t.Fatalf("the being could not reach onward: %v", c.relay.err)
	}
	// What actually crossed, read at the door it crossed to.
	onward, err := envelope.OpenSay(secret("far/padlock"), c.relay.message)
	if err != nil {
		c.t.Fatal(err)
	}
	return onward
}

// TestEveryDoorHandsOnwardLessThanItReceived is the whole of the leash's
// arithmetic: the hop count falls by one at every door, and the time budget
// falls by that door's own dwell.
func TestEveryDoorHandsOnwardLessThanItReceived(t *testing.T) {
	c := link(t, 30)
	onward := c.pass(1, envelope.Allowance{Time: 5000, Hops: 8})
	if onward.Allowance.Hops != 7 {
		t.Fatalf("eight hops arrived and %d went onward", onward.Allowance.Hops)
	}
	if onward.Allowance.Time != 4970 {
		t.Fatalf("five thousand milliseconds arrived, thirty were spent, and %d went onward", onward.Allowance.Time)
	}
}

// TestTheRoadIsNeverCounted holds that time spent between doors is on nobody's
// clock. The dwell is two readings of one clock, so a middle door that idles
// between calls spends nothing of the budget it was not working through.
func TestTheRoadIsNeverCounted(t *testing.T) {
	c := link(t, 30)
	c.pass(1, envelope.Allowance{Time: 5000, Hops: 8})
	// A long silence, on the road rather than at the door.
	c.middle.clock.step(100_000)
	onward := c.pass(2, envelope.Allowance{Time: 5000, Hops: 8})
	if onward.Allowance.Time != 4970 {
		t.Fatalf("the road cost the second call %d milliseconds", 5000-onward.Allowance.Time)
	}
}

// TestABeingCannotWidenTheLeash holds that the allowance is the caller's and
// no door beneath may widen it. A being under a leash hands the leash on, and
// what it wrote in Allowance is never read.
func TestABeingCannotWidenTheLeash(t *testing.T) {
	c := link(t, 0)
	// The relay names a generous allowance of its own beside the leash.
	c.relay.w = c.middle.w
	onward := c.passWidening(1, envelope.Allowance{Time: 5000, Hops: 2})
	if onward.Allowance.Hops != 1 || onward.Allowance.Time != 5000 {
		t.Fatalf("a being widened its own leash to %v", onward.Allowance)
	}
}

// passWidening is pass with the being asking for more than it holds.
func (c *chain) passWidening(seq int64, a envelope.Allowance) envelope.Say {
	c.t.Helper()
	c.relay.greedy = true
	return c.pass(seq, a)
}

// TestABudgetThatRanOutMidWorkIsRefused holds the far side of step six. A door
// judges the leash on arrival, but a being that works past the budget cannot
// hand on what is no longer there.
func TestABudgetThatRanOutMidWorkIsRefused(t *testing.T) {
	c := link(t, 200)
	s := c.middle.say(c.middle.inv.Heir, 1)
	s.Being = &c.middle.being
	s.Method = &envelope.Method{Name: "pass", Args: []byte{}}
	// A hundred milliseconds is a legal leash on arrival, and gone by the time
	// two hundred have been spent on the work.
	s.Allowance = envelope.Allowance{Time: 100, Hops: 4}
	next := arithmetic.Commit(c.middle.w.Name(), arithmetic.SigningKey(secret("caller/ownHeir")))
	s.Commitment = &next
	// The being's own failure is silence at the door, like any other: a warden
	// is the global try/catch and never narrates what happened behind it.
	c.middle.silent(c.middle.judge(c.middle.inv.HeirSecret, s))
}

// TestTheLastHopHandsOnZero holds the hop count's own end. One hop arriving
// hands on zero, and zero is a leash a door still judges: what it forbids is
// the hop after it, not the call it arrives on.
func TestTheLastHopHandsOnZero(t *testing.T) {
	c := link(t, 0)
	onward := c.pass(1, envelope.Allowance{Time: 5000, Hops: 1})
	if onward.Allowance.Hops != 0 {
		t.Fatalf("one hop arrived and %d went onward", onward.Allowance.Hops)
	}
}

// TestZeroHopsGoesNoFurther holds the other side of the same boundary. Zero
// hops is a legal leash to arrive with — the door judges it and the being does
// its work — and the onward ask under it is simply never made.
func TestZeroHopsGoesNoFurther(t *testing.T) {
	c := link(t, 0)
	s := c.middle.say(c.middle.inv.Heir, 1)
	s.Being = &c.middle.being
	s.Method = &envelope.Method{Name: "pass", Args: []byte{}}
	s.Allowance = envelope.Allowance{Time: 5000, Hops: 0}
	next := arithmetic.Commit(c.middle.w.Name(), arithmetic.SigningKey(secret("caller/ownHeir")))
	s.Commitment = &next
	// This being answers only what it managed to send onward, so its refusal to
	// reach further is silence at its own door. What the ruling holds is that
	// nothing left this ground.
	c.middle.silent(c.middle.judge(c.middle.inv.HeirSecret, s))
	if c.relay.err == nil {
		t.Fatal("an ask was made under a leash with no hop left")
	}
	if c.relay.message != nil {
		t.Fatal("bytes left this ground under a spent leash")
	}
}

// TestAClockThatWentBackwardsDoesNotWiden holds that a broken clock is a
// broken clock rather than a licence. Two readings of one clock is what the
// dwell is, and a negative one hands on no more than arrived.
func TestAClockThatWentBackwardsDoesNotWiden(t *testing.T) {
	c := link(t, -400)
	onward := c.pass(1, envelope.Allowance{Time: 5000, Hops: 8})
	if onward.Allowance.Time != 5000 {
		t.Fatalf("a backwards clock handed on %d of 5000 milliseconds", onward.Allowance.Time)
	}
}

// TestADoorWithNoClockCannotStand holds the rule the clock is taken by: it is
// an argument, never reached for, and a door that has not been given one
// cannot shrink a leash and so cannot stand in a chain at all.
func TestADoorWithNoClockCannotStand(t *testing.T) {
	if _, err := warden.New(warden.Founding{
		NameSecret:    secret("clockless/name"),
		PadlockSecret: secret("clockless/padlock"),
	}); err == nil {
		t.Fatal("a door with no clock stood up")
	}
}

// TestALeashOutsideAJudgmentCannotBeSpent holds the zero value: a being called
// by its own host, rather than through a door, holds no allowance and may
// spend none.
func TestALeashOutsideAJudgmentCannotBeSpent(t *testing.T) {
	var l warden.Leash
	if _, err := l.Onward(); err == nil {
		t.Fatal("a call that came through no door handed something onward")
	}
	if a := l.Received(); a.Time != 0 || a.Hops != 0 {
		t.Fatalf("a leash from nowhere carries %v", a)
	}
}
