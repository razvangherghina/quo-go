// Part one of papers/quo-truth.md: what the warden provides. Written from the
// paper alone. Every case here is a sentence of that part made checkable.
package warden_test

import (
	"context"
	"crypto/rand"
	"slices"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/warden"
)

const counterText = `Counter
  bump() int
  read() int
`

// Counter is a plain Go value. It never learns it has an address, judges
// nothing, and sees no key.
type Counter struct {
	warden.Attach
	n int64
}

func (c *Counter) Bump() int64 { c.n++; return c.n }
func (c *Counter) Read() int64 { return c.n }

func draw() [32]byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b
}

func still() int64 { return 1000 }

func open(t *testing.T, delivery warden.Delivery, seeds [3][32]byte, store warden.Store) *warden.Warden {
	t.Helper()
	w, err := warden.New(warden.Founding{
		NameSecret:     seeds[0],
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(seeds[0]), arithmetic.SigningKey(seeds[2])),
		PadlockSecret:  seeds[1],
		// The one fact the law makes a warden publish about itself, so what a
		// caller reads back off a handle is a number and not a default.
		Limit:    1 << 20,
		Clock:    still,
		Random:   draw,
		Delivery: delivery,
		Store:    store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func seeds() [3][32]byte { return [3][32]byte{draw(), draw(), draw()} }

// pair is two grounds in one process, reached by a delivery that hands bytes
// straight to the far warden's one entry point. No road, no socket, and no step
// waived.
func pair(t *testing.T) (*warden.Warden, *warden.Warden, *warden.Memory) {
	t.Helper()
	d := warden.NewMemory()
	alice := open(t, d, seeds(), nil)
	bob := open(t, d, seeds(), nil)
	d.Attach("mem://alice", alice)
	d.Attach("mem://bob", bob)
	alice.Publish("mem://alice")
	bob.Publish("mem://bob")
	return alice, bob, d
}

func TestOneEntryPointAnswersBytesOrSilence(t *testing.T) {
	alice, bob, _ := pair(t)
	counter := &Counter{}
	being, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(bob.Accept(context.Background(), inv, warden.Accepting{Label: "counter"}))
	if err != nil {
		t.Fatal(err)
	}

	// An ask arriving is judged and answered.
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}
	// Garbage arriving is silence, and the door says nothing about why.
	if back := alice.Arrive([]byte("not an envelope"), nil); back != nil {
		t.Fatal("garbage was answered")
	}
	if back := alice.Arrive(nil, nil); back != nil {
		t.Fatal("nothing was answered")
	}
	if being == ([32]byte{}) {
		t.Fatal("a being with no name")
	}
}

func TestCallerIsOfferedAsAFact(t *testing.T) {
	alice, bob, _ := pair(t)
	counter := &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	var seen []warden.Caller
	alice.Offer(func(c warden.Caller) { seen = append(seen, c) })
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(bob.Accept(context.Background(), inv, warden.Accepting{Label: "counter"}))
	if err != nil {
		t.Fatal(err)
	}
	handle.Call(context.Background(), "bump")

	// Accepting is two rotations and a blueprint ask; the call after them is a
	// plain ask by a holder.
	if len(seen) == 0 {
		t.Fatal("the house was told nothing")
	}
	if seen[0].Kind != warden.CallerRotation {
		t.Fatalf("the first caller was %q", seen[0].Kind)
	}
	last := seen[len(seen)-1]
	if last.Kind != warden.CallerHolder {
		t.Fatalf("the last caller was %q", last.Kind)
	}
	if last.Voice == ([32]byte{}) {
		t.Fatal("a caller with no voice")
	}
}

func TestStandingsAreVoicesOnly(t *testing.T) {
	alice, bob, _ := pair(t)
	counter := &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	if held := counter.Quo().Standings(); len(held) != 0 {
		t.Fatalf("a fresh being holds %d standings", len(held))
	}
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Accept(context.Background(), inv, warden.Accepting{Label: "counter"}); err != nil {
		t.Fatal(err)
	}
	held := counter.Quo().Standings()
	if len(held) != 1 {
		t.Fatalf("one accept left %d standings", len(held))
	}
	// A voice and nothing else: the type itself carries no mark, no window, no
	// padlock and no hint.
	if held[0] == ([32]byte{}) {
		t.Fatal("a standing with no voice")
	}
}

func TestGrantNamesTheBeingAndReleaseTakesEveryStandingWithIt(t *testing.T) {
	alice, bob, _ := pair(t)
	counter, other := &Counter{}, &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	at, _, err := alice.Hold(other, warden.Holding{Blueprint: counterText})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := counter.Quo().Grant(&at)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(bob.Accept(context.Background(), inv, warden.Accepting{Label: "other"}))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}
	// Bob reaches `other` and not `counter`.
	if len(other.Quo().Standings()) != 1 || len(counter.Quo().Standings()) != 0 {
		t.Fatal("the grant opened the wrong being")
	}
	// Released: Bob's next call meets silence, indistinguishable from anything.
	counter.Quo().Release(at)
	if _, ok := handle.Call(context.Background(), "bump"); ok {
		t.Fatal("a released being answered")
	}
}

func TestHoldMintsASmallerBeingBesideMe(t *testing.T) {
	alice, _, _ := pair(t)
	counter := &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	small, handle, err := counter.Quo().Hold(&Counter{}, warden.Holding{Blueprint: counterText, Label: "small"})
	if err != nil {
		t.Fatal(err)
	}
	// Same warden, same shape: leashed, a value or silence, and no seal.
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}
	if v, ok := counter.Quo().Relation("small").Call(context.Background(), "read"); !ok || v.(int64) != 1 {
		t.Fatalf("read answered %v %v", v, ok)
	}
	counter.Quo().Release(small)
	if _, ok := handle.Call(context.Background(), "read"); ok {
		t.Fatal("a released neighbour answered")
	}
}

func TestWhyItFellSilentIsToldInward(t *testing.T) {
	alice, _, _ := pair(t)
	var reasons []error
	alice.Observe(func(s warden.Silence) { reasons = append(reasons, s.Reason) })
	if back := alice.Arrive([]byte("garbage"), nil); back != nil {
		t.Fatal("garbage was answered")
	}
	if len(reasons) == 0 || reasons[0] == nil {
		t.Fatal("the house was told nothing")
	}
}

func TestAHintIsCarriedAsAnOpaqueString(t *testing.T) {
	alice, bob, _ := pair(t)
	counter := &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	alice.Publish("anything at all, even this")
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(inv.Hints, "anything at all, even this") {
		t.Fatal("the warden read the hint it was given")
	}
	// Delivery walks past what it cannot speak; the door still answers on the
	// road it can.
	handle, err := sole(bob.Accept(context.Background(), inv, warden.Accepting{Label: "counter"}))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}
}

func TestWhatMustSurviveARestartLivesInTheStore(t *testing.T) {
	d := warden.NewMemory()
	store := &warden.MemoryStore{}
	aliceSeeds := seeds()
	alice := open(t, d, aliceSeeds, store)
	bob := open(t, d, seeds(), nil)
	d.Attach("mem://alice", alice)
	d.Attach("mem://bob", bob)
	alice.Publish("mem://alice")
	bob.Publish("mem://bob")

	counter := &Counter{}
	keys := warden.Keys{Secret: draw(), HeirSecret: draw()}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(bob.Accept(context.Background(), inv, warden.Accepting{Label: "counter"}))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}
	spent, err := handle.Seal(context.Background(), "bump")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Send(context.Background(), spent); !ok || v.(int64) != 2 {
		t.Fatalf("the sealed bump answered %v %v", v, ok)
	}

	// The process dies. A new warden opens on the same seeds and the same
	// store, holds the same object again on the same keys, and Bob's standing
	// is still there.
	again := open(t, d, aliceSeeds, store)
	d.Attach("mem://alice", again)
	fresh := &Counter{}
	if _, _, err := again.Hold(fresh, warden.Holding{Blueprint: counterText, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	if held := fresh.Quo().Standings(); len(held) != 1 {
		t.Fatalf("the restart kept %d standings", len(held))
	}
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("after the restart bump answered %v %v", v, ok)
	}
	// The marks survived too: the envelope spent before the restart is silence.
	if _, ok := handle.Send(context.Background(), spent); ok {
		t.Fatal("a number spent before the restart was honoured after it")
	}
}

// What a ground offers a voice that merely knocks is a record like any other:
// a door that forgot it on a restart would quietly stop serving the thing it
// was standing there to serve.
func TestWhatAWardenExposesSurvivesARestart(t *testing.T) {
	d := warden.NewMemory()
	store := &warden.MemoryStore{}
	aliceSeeds := seeds()
	alice := open(t, d, aliceSeeds, store)
	d.Attach("mem://alice", alice)
	alice.Publish("mem://alice")

	counter := &Counter{}
	keys := warden.Keys{Secret: draw(), HeirSecret: draw()}
	being, _, err := alice.Hold(counter, warden.Holding{
		Blueprint: counterText, Keys: keys, Public: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	again := open(t, d, aliceSeeds, store)
	d.Attach("mem://alice", again)
	fresh := &Counter{}
	if _, _, err := again.Hold(fresh, warden.Holding{Blueprint: counterText, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	// Held again without Public, and still exposed: the store is what says so.
	if !again.Conceal(being) {
		t.Fatal("the restart did not keep what the door exposes")
	}
}

// A ground that knocks at a door as a stranger and later accepts an invitation
// there holds two rows at that one far warden, each with its own voice. A
// label resolved by warden and holder alone lands on whichever came first —
// the knock's — and every ask down it is signed by a key with no standing.
func TestALabelFindsTheRowItNamedAndNotTheFirstAtThatWarden(t *testing.T) {
	d := warden.NewMemory()
	store := &warden.MemoryStore{}
	bobSeeds := seeds()
	alice := open(t, d, seeds(), nil)
	bob := open(t, d, bobSeeds, store)
	d.Attach("mem://alice", alice)
	d.Attach("mem://bob", bob)
	alice.Publish("mem://alice")
	bob.Publish("mem://bob")

	counter := &Counter{}
	if _, _, err := alice.Hold(counter, warden.Holding{Blueprint: counterText}); err != nil {
		t.Fatal(err)
	}
	holder := &Counter{}
	keys := warden.Keys{Secret: draw(), HeirSecret: draw()}
	if _, _, err := bob.Hold(holder, warden.Holding{Blueprint: counterText, Keys: keys}); err != nil {
		t.Fatal(err)
	}

	// The stranger's row is made first, so a match that ignores the voice
	// takes it.
	if _, err := holder.Quo().Knock(alice.Card(nil), ""); err != nil {
		t.Fatal(err)
	}
	inv, err := counter.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := sole(holder.Quo().Accept(context.Background(), inv, "counter"))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(context.Background(), "bump"); !ok || v.(int64) != 1 {
		t.Fatalf("bump answered %v %v", v, ok)
	}

	again := open(t, d, bobSeeds, store)
	d.Attach("mem://bob", again)
	fresh := &Counter{}
	if _, _, err := again.Hold(fresh, warden.Holding{Blueprint: counterText, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	byLabel := again.Relation("counter")
	if byLabel == nil {
		t.Fatal("the label came back at no row")
	}
	if v, ok := byLabel.Call(context.Background(), "bump"); !ok || v.(int64) != 2 {
		t.Fatalf("the label's row answered %v %v", v, ok)
	}
}
