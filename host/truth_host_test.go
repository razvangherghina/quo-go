// Part three of papers/quo-truth.md: what the host does. The same being,
// unchanged, is installed under a warden reached by three roads and gives the
// same answers; a tab that publishes nothing is pushed to down the line it
// holds; a closed tab is weather. Written from the paper alone.
package host_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"quo.systems/kit/host"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// sole is the handle of a standing that names one being, with the accept's own
// answer held to that.
func sole(handles []warden.Handle, err error) (warden.Handle, error) {
	if err != nil {
		return nil, err
	}
	if len(handles) != 1 {
		return nil, fmt.Errorf("the standing answered %d handles", len(handles))
	}
	return handles[0], nil
}

const dogText = `Dog
  name() text
  logWalk(minutes int) bool
`

// Dog is written once, about its behaviour, and installed anywhere. Nothing on
// it names a road or a host.
type Dog struct {
	warden.Attach
	walks []int64
}

func (d *Dog) Name() string { return "Rex" }
func (d *Dog) LogWalk(minutes int64) bool {
	d.walks = append(d.walks, minutes)
	return true
}

const inboxText = `Inbox
  walked(minutes int)
`

type Inbox struct {
	warden.Attach
	heard []int64
}

func (i *Inbox) Walked(minutes int64) { i.heard = append(i.heard, minutes) }

const walkerText = `Walker
  subscribe(inbox invitation) bool
  walk(minutes int) bool
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
	if w.listener != nil {
		w.listener.Call(ctx, "walked", minutes)
	}
	return true
}

func stand(t *testing.T, roads ...string) *host.Host {
	t.Helper()
	h, err := host.Open(host.Standing{Roads: roads})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTheSameDogBehindEveryRoadGivesTheSameAnswers(t *testing.T) {
	for _, road := range []string{host.HTTP, host.Line, host.InProcess} {
		t.Run(road, func(t *testing.T) {
			alice := stand(t, road)
			defer alice.Close()
			bob := stand(t, road)
			defer bob.Close()

			rex := &Dog{}
			if _, _, err := alice.Warden.Hold(rex, warden.Holding{Blueprint: dogText}); err != nil {
				t.Fatal(err)
			}
			inv, err := rex.Quo().Grant(nil)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := sole(bob.Warden.Accept(context.Background(), inv, warden.Accepting{Label: "rex"}))
			if err != nil {
				t.Fatal(err)
			}
			if v, ok := handle.Call(context.Background(), "name"); !ok || v.(string) != "Rex" {
				t.Fatalf("name answered %v %v", v, ok)
			}
			if v, ok := handle.Call(context.Background(), "logWalk", int64(12)); !ok || v != true {
				t.Fatalf("logWalk answered %v %v", v, ok)
			}
			if len(rex.walks) != 1 || rex.walks[0] != 12 {
				t.Fatalf("Rex was walked %v", rex.walks)
			}
		})
	}
}

func TestAHintTheCallerCannotSpeakIsWalkedPast(t *testing.T) {
	// Alice publishes a road nobody here can speak, first, and HTTP after it.
	alice, err := host.Open(host.Standing{Roads: []string{host.HTTP}, Hints: []string{"pigeon://loft"}})
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob := stand(t, host.HTTP)
	defer bob.Close()

	rex := &Dog{}
	if _, _, err := alice.Warden.Hold(rex, warden.Holding{Blueprint: dogText}); err != nil {
		t.Fatal(err)
	}
	inv, err := rex.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Hints) != 2 || inv.Hints[0] != "pigeon://loft" {
		t.Fatalf("the invitation offered %v", inv.Hints)
	}
	handle, err := sole(bob.Warden.Accept(context.Background(), inv, warden.Accepting{Label: "rex"}))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := handle.Call(context.Background(), "name"); !ok || v.(string) != "Rex" {
		t.Fatalf("name answered %v %v", v, ok)
	}
}

func TestATabPublishesNothingAndIsPushedToDownTheLineItHolds(t *testing.T) {
	// Bob's laptop listens. Alice's tab has no road of its own and dials out.
	laptop := stand(t, host.Line)
	defer laptop.Close()
	tab := stand(t)
	defer tab.Close()

	walker, inbox := &Walker{}, &Inbox{}
	if _, _, err := laptop.Warden.Hold(walker, warden.Holding{Blueprint: walkerText}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tab.Warden.Hold(inbox, warden.Holding{Blueprint: inboxText}); err != nil {
		t.Fatal(err)
	}
	if len(tab.Warden.Hints()) != 0 {
		t.Fatalf("a tab published %v", tab.Warden.Hints())
	}

	granted, err := walker.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := sole(inbox.Quo().Accept(context.Background(), granted, "walker"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := inbox.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := bob.Call(context.Background(), "subscribe", back); !ok || v != true {
		t.Fatalf("subscribe answered %v %v", v, ok)
	}
	bob.Call(context.Background(), "walk", int64(9))
	bob.Call(context.Background(), "walk", int64(11))
	if len(inbox.heard) != 2 || inbox.heard[0] != 9 || inbox.heard[1] != 11 {
		t.Fatalf("the tab heard %v", inbox.heard)
	}
}

func TestAClosedTabIsWeather(t *testing.T) {
	laptop := stand(t, host.Line)
	defer laptop.Close()
	tab := stand(t)

	walker, inbox := &Walker{}, &Inbox{}
	if _, _, err := laptop.Warden.Hold(walker, warden.Holding{Blueprint: walkerText}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tab.Warden.Hold(inbox, warden.Holding{Blueprint: inboxText}); err != nil {
		t.Fatal(err)
	}
	granted, err := walker.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := sole(inbox.Quo().Accept(context.Background(), granted, "walker"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := inbox.Quo().Grant(nil)
	if err != nil {
		t.Fatal(err)
	}
	bob.Call(context.Background(), "subscribe", back)
	bob.Call(context.Background(), "walk", int64(1))
	tab.Close()
	// The line takes a moment to be noticed shut at the far end; what matters
	// is that when it is, the push is weather and nothing falls over.
	time.Sleep(50 * time.Millisecond)

	// Walker's own answer to itself is unaffected; only the push found nobody.
	// The call comes from this test rather than down the dead line, so it is
	// made through the being the laptop still holds.
	if !walker.Walk(context.Background(), 2) {
		t.Fatal("the source itself fell over when its subscriber died")
	}
	if len(inbox.heard) != 1 || inbox.heard[0] != 1 {
		t.Fatalf("the closed tab heard %v", inbox.heard)
	}
}

func TestWhatDeliveryIsGivenIsTheWayBackAndNothingElse(t *testing.T) {
	// The row is the whole of what crosses from the warden to delivery, and it
	// is an address and a list of opaque strings. A host holds no secret.
	row := reflect.TypeOf(warden.Row{})
	if row.NumField() != 2 {
		t.Fatalf("a row carries %d fields", row.NumField())
	}
	if _, ok := row.FieldByName("Padlock"); !ok {
		t.Fatal("a row carries no padlock")
	}
	if _, ok := row.FieldByName("Hints"); !ok {
		t.Fatal("a row carries no hints")
	}
	// And the one call downward is an address beside an opaque token, with
	// nothing coming back.
	arrived, ok := reflect.TypeOf((*warden.Delivery)(nil)).Elem().MethodByName("Arrived")
	if !ok {
		t.Fatal("delivery is never told where a padlock's asks arrive")
	}
	if arrived.Type.NumOut() != 0 {
		t.Fatal("the warden's one call downward hands something back")
	}
	if arrived.Type.In(0) != reflect.TypeOf([32]byte{}) {
		t.Fatal("the warden hands down something other than an address")
	}
	if arrived.Type.In(1).Kind() != reflect.Interface {
		t.Fatal("the road handed down is not an opaque token")
	}
}
