package carriage_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
	"quo.systems/kit/notation"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

const todoText = "ToDo\n  add(title text) text\n  count() int\n"

type todo struct {
	warden.Attach
	items []string
}

func (o *todo) Add(title string) string {
	o.items = append(o.items, title)
	return title
}

func (o *todo) Count() int64 { return int64(len(o.items)) }

// secret is a fixed thirty-two byte draw, so nothing here is random or timed.
func secret(label string) [32]byte { return arithmetic.Hash([]byte("quo-go-carriage/" + label)) }

// tick is a clock the bench holds and moves by hand, in milliseconds. A door's
// clock is handed to it for the same reason its randomness is.
type tick struct{ ms int64 }

func (c *tick) read() int64   { return c.ms }
func (c *tick) step(ms int64) { c.ms += ms }

func stand(t *testing.T, label string) *warden.Warden {
	return standAt(t, label, (&tick{}).read)
}

func standAt(t *testing.T, label string, clock func() int64) *warden.Warden {
	t.Helper()
	name := secret(label + "/name")
	at := 0
	w, err := warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(secret(label+"/wardenHeir"))),
		PadlockSecret:  secret(label + "/padlock"),
		Limit:          1 << 20,
		Clock:          clock,
		// A fixed sequence, so nothing here is random.
		Random: func() [32]byte {
			at++
			return secret(fmt.Sprintf("%s/draw/%d", label, at))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// serve hangs a door on the common carriage. The draws a judgment needs are
// fixed, so the bench is not random and not timed.
func serve(t *testing.T, w *warden.Warden, label string) *httptest.Server {
	t.Helper()
	n := 0
	w.Observe(func(s warden.Silence) {
		// Silence is the whole of every refusal, and the reason stays here.
		t.Logf("%s refused a message: %v", label, s.Reason)
	})
	s := httptest.NewServer(carriage.Handler(w.Limit(), func(message []byte) []byte {
		n++
		// The common carriage holds no line, so there is no road token to hand
		// down: an answer rides the response it came in on.
		return w.Arrive(message, nil)
	}))
	t.Cleanup(s.Close)
	return s
}

// TestOneMessageCrossesTheCarriage drives one real POST between two grounds
// that share nothing but an invitation: the caller seals, the road carries
// bytes and nothing else, and the door's answer comes back in the body.
func TestOneMessageCrossesTheCarriage(t *testing.T) {
	house := stand(t, "house")
	being, _, err := house.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("being"), HeirSecret: secret("beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	door := serve(t, house, "house")

	inv, err := house.GrantAs(being,
		warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")},
		house.Padlock(), []string{door.URL})
	if err != nil {
		t.Fatal(err)
	}

	caller := stand(t, "caller")
	// The holder stands with the heir it was handed: whoever minted a voice
	// has seen its keys, so the first act is a rotate-and-ask to a key nobody
	// else has ever seen.
	caller.Stand(caller.Self(), inv, inv.HeirSecret)
	mine := secret("callerHeir")

	// Claiming a standing the moment the secret arrives is legal and
	// observable: rotate, ask nothing, and what comes back is what you stand
	// at.
	message, seq, err := caller.Ask(warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Hints:     []string{"https://caller.example"},
		NextHeir:  &mine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Fatalf("the first legal number is one, got %d", seq)
	}

	reply, err := carriage.Caller{}.Send(inv.Hints, message)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil {
		t.Fatal("the door answered silence")
	}

	answer, err := caller.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Warden != house.Name() {
		t.Fatal("the door that answered is not the door that was asked")
	}
	if answer.Seq != seq {
		t.Fatalf("the answer names ask %d, not %d", answer.Seq, seq)
	}

	estate, err := readEstate(answer.Data)
	if err != nil {
		t.Fatal(err)
	}
	// The public being is reachable by everyone, holders included, so the
	// estate holds two classes: the granted being's, and the Warden's own.
	if len(estate) != 2 {
		t.Fatalf("the estate holds %d classes, want 2", len(estate))
	}
	if !estate[warden.Digest] {
		t.Fatal("the public being is missing from the estate")
	}
}

// TestTheSecondAskContinuesTheCount holds that the count only rises for one
// voice across the carriage, and that the door spends each number once.
func TestTheSecondAskContinuesTheCount(t *testing.T) {
	house := stand(t, "house")
	being, _, err := house.Hold(&todo{}, warden.Holding{
		Blueprint: todoText,
		Keys:      warden.Keys{Secret: secret("being"), HeirSecret: secret("beingHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	door := serve(t, house, "house")
	inv, err := house.GrantAs(being,
		warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")},
		house.Padlock(), []string{door.URL})
	if err != nil {
		t.Fatal(err)
	}

	caller := stand(t, "caller")
	caller.Stand(caller.Self(), inv, inv.HeirSecret)
	mine := secret("callerHeir")

	ask := func(r warden.Reach) (envelope.Answer, []byte) {
		t.Helper()
		message, _, err := caller.Ask(r)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := carriage.Caller{}.Send([]string{door.URL}, message)
		if err != nil {
			t.Fatal(err)
		}
		if reply == nil {
			t.Fatal("the door answered silence")
		}
		a, err := caller.Hear(reply)
		if err != nil {
			t.Fatal(err)
		}
		return a, message
	}

	base := warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Hints:     []string{"https://caller.example"},
	}

	rotate := base
	rotate.NextHeir = &mine
	first, _ := ask(rotate)
	if first.Seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d, want 1", first.Seq)
	}

	// A field on the being it now reaches, over the same road.
	call := base
	call.Being = &being
	call.Method = &envelope.Method{Name: "count", Args: []byte{}}
	second, replayed := ask(call)
	if second.Seq != 2 {
		t.Fatalf("the second ask spent %d, want 2", second.Seq)
	}

	// A thief replaying yesterday's bytes replays yesterday's number, and the
	// door has already spent it. Silence's wire form is an empty body.
	again, err := carriage.Caller{}.Send([]string{door.URL}, replayed)
	if err != nil {
		t.Fatal(err)
	}
	if again != nil {
		t.Fatal("a replayed message was answered")
	}
}

// TestTheCarriageCarriesNothingElse holds the three things the road is allowed
// to say: anything that is not a POST is silence, a body over the door's
// published limit is silence, and no status code is read on the way back.
func TestTheCarriageCarriesNothingElse(t *testing.T) {
	answered := false
	s := httptest.NewServer(carriage.Handler(8, func(message []byte) []byte {
		answered = true
		return append([]byte("seen:"), message...)
	}))
	t.Cleanup(s.Close)

	res, err := http.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if answered {
		t.Fatal("a GET reached the door")
	}

	over, err := carriage.Caller{}.Send([]string{s.URL}, []byte("123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if over != nil || answered {
		t.Fatal("a body over the limit reached the door")
	}

	under, err := carriage.Caller{}.Send([]string{s.URL}, []byte("12345678"))
	if err != nil {
		t.Fatal(err)
	}
	if string(under) != "seen:12345678" {
		t.Fatalf("the body did not come back whole: %q", under)
	}
}

// TestACallerTriesEveryRoad holds that a hint is a guess about the weather: a
// road that fails to carry moves the caller to the next, and a road that
// answered silence does not.
func TestACallerTriesEveryRoad(t *testing.T) {
	reached := 0
	s := httptest.NewServer(carriage.Handler(64, func([]byte) []byte {
		reached++
		return nil // silence
	}))
	t.Cleanup(s.Close)

	// A dead road first, then a live one.
	reply, err := carriage.Caller{}.Send([]string{"http://127.0.0.1:1/", s.URL}, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil {
		t.Fatal("silence is no bytes")
	}
	if reached != 1 {
		t.Fatalf("the door was reached %d times, want 1", reached)
	}

	// Silence is a door speaking, so the caller stops there rather than asking
	// the same question down the next road.
	if _, err := (carriage.Caller{}).Send([]string{s.URL, s.URL}, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if reached != 2 {
		t.Fatalf("the door was reached %d times, want 2", reached)
	}

	// Every road dead is not an answer, and says so.
	if _, err := (carriage.Caller{}).Send([]string{"http://127.0.0.1:1/"}, []byte("hello")); err == nil {
		t.Fatal("a message that never left was reported as delivered")
	}
}

// readEstate pulls the digests out of a describe's answer, which rides as the
// Warden blueprint's own `estate` record.
func readEstate(data []byte) (map[[32]byte]bool, error) {
	v, err := wire.Decode(warden.Own, notation.RecordType("estate"), data)
	if err != nil {
		return nil, err
	}
	fields, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("the estate is not a record")
	}
	classes, ok := fields["classes"].([]any)
	if !ok {
		return nil, errors.New("the estate has no classes")
	}
	out := map[[32]byte]bool{}
	for _, c := range classes {
		f, ok := c.(map[string]any)
		if !ok {
			return nil, errors.New("a class is not a record")
		}
		d, ok := f["digest"].([32]byte)
		if !ok {
			return nil, errors.New("a class has no digest")
		}
		out[d] = true
	}
	return out, nil
}
