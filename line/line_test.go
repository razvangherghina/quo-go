package line_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
	"quo.systems/kit/line"
	"quo.systems/kit/warden"
)

const todoText = "ToDo\n  add(title text) text\n  count() int\n"

type todo struct{ items []string }

func (o *todo) Invoke(call warden.Call) ([]byte, error) {
	switch call.Method {
	case "add":
		o.items = append(o.items, string(call.Args[8:]))
		return call.Args, nil
	case "count":
		out := make([]byte, 8)
		binary.BigEndian.PutUint64(out, uint64(len(o.items)))
		return out, nil
	}
	return nil, errors.New("the blueprint declares no such field")
}

// secret is a fixed thirty-two byte draw, so nothing here is random or timed.
func secret(label string) [32]byte { return arithmetic.Hash([]byte("quo-go-line/" + label)) }

// text writes one text argument the way the wire encoding does: its length as
// an int, then the bytes.
func text(s string) []byte {
	out := make([]byte, 8+len(s))
	binary.BigEndian.PutUint64(out[:8], uint64(len(s)))
	copy(out[8:], s)
	return out
}

func stand(t *testing.T, label string, limit int64) *warden.Warden {
	t.Helper()
	name := secret(label + "/name")
	w, err := warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(secret(label+"/wardenHeir"))),
		PadlockSecret:  secret(label + "/padlock"),
		Limit:          limit,
		Clock:          func() int64 { return 1000 },
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// door is one ground's half of a line: judgment with fixed draws, and the
// opening of an answer under this ground's own padlock. A warden is not itself
// concurrent, and one ground here holds several lines at once, so the two are
// taken under one lock.
func door(w *warden.Warden, label string) line.Door {
	var mu sync.Mutex
	return line.Door{
		Judge: func(message []byte) []byte {
			mu.Lock()
			defer mu.Unlock()
			reply, err := w.Judge(warden.Draws{
				Ephemeral: secret(label + "/answerEphemeral"),
				Heir:      secret(label + "/receiveHeir"),
			}, message)
			if err != nil {
				// Silence is the whole of every refusal, and on this carriage
				// it has no wire form at all.
				return nil
			}
			return reply
		},
		Hear: func(message []byte) (envelope.Answer, error) {
			return envelope.OpenAnswer(w.PadlockSecret(), message)
		},
		Limit: w.Limit(),
	}
}

// raw opens the plain wire to a hint, for the cases that are about framing
// rather than about Quo.
func raw(t *testing.T, hint string) net.Conn {
	t.Helper()
	at, _, _ := strings.Cut(strings.TrimPrefix(hint, "tcp://"), "?")
	conn, err := net.Dial("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func header(n int64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(n))
	return out
}

// dropped holds that the peer closed without a word: nothing was ever written
// back, and the read ends rather than waiting.
func dropped(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	said, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("the line was not dropped: %v", err)
	}
	if len(said) != 0 {
		t.Fatalf("the peer said %d bytes before dropping the line", len(said))
	}
}

// waited reads one value off a carry, or reports that nothing came back.
func waited(answers <-chan []byte) ([]byte, bool) {
	select {
	case reply := <-answers:
		return reply, true
	case <-time.After(300 * time.Millisecond):
		return nil, false
	}
}

// stranger seals a say from a voice that stands nowhere, which is what a
// refused ask looks like on the wire.
func stranger(t *testing.T, to *warden.Warden, being [32]byte) []byte {
	t.Helper()
	message, err := envelope.SealSay(secret("strangerEphemeral"), to.Padlock(), secret("stranger"), envelope.Say{
		Voice:     arithmetic.SigningKey(secret("stranger")),
		Recipient: to.Name(),
		Seq:       1,
		Padlock:   to.Padlock(),
		Allowance: envelope.Allowance{Time: 5000, Hops: 4},
		Being:     &being,
		Method:    &envelope.Method{Name: "count", Args: []byte{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// house stands a listening ground holding one todo being, and hands back
// everything a caller needs to reach it.
type house struct {
	warden   *warden.Warden
	being    [32]byte
	object   *todo
	listener *line.Listener
	accepted chan *line.Line
}

func listening(t *testing.T, limit int64) *house {
	t.Helper()
	w := stand(t, "house", limit)
	object := &todo{}
	being, err := w.Hold(todoText, object, warden.Keys{Secret: secret("being"), HeirSecret: secret("beingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *line.Line, 4)
	listener, err := line.Listen(door(w, "house"), "127.0.0.1:0", func(l *line.Line) { accepted <- l })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return &house{warden: w, being: being, object: object, listener: listener, accepted: accepted}
}

// visiting mints a caller that stands at the house's being and holds a line to
// it. The first ask down that line is a rotate-and-ask, because whoever minted
// a voice has seen its keys.
func visiting(t *testing.T, h *house) (*warden.Warden, *line.Line) {
	t.Helper()
	inv, err := h.warden.Grant(h.being,
		warden.Keys{Secret: secret("voice"), HeirSecret: secret("voiceHeir")},
		h.warden.Padlock(), []string{h.listener.Hint})
	if err != nil {
		t.Fatal(err)
	}
	guest := stand(t, "guest", 1<<20)
	guest.Stand(guest.Self(), inv, inv.HeirSecret)
	l, err := line.Dial(door(guest, "guest"), h.listener.Hint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return guest, l
}

// ask seals one reach, carries it, and opens what comes back.
func ask(t *testing.T, from *warden.Warden, l *line.Line, r warden.Reach) envelope.Answer {
	t.Helper()
	message, seq, err := from.Ask(secret("askEphemeral"), r)
	if err != nil {
		t.Fatal(err)
	}
	reply, came := waited(l.Carry(message, &line.Expect{Warden: r.Far, Seq: seq}))
	if !came || reply == nil {
		t.Fatal("nothing came back down the line")
	}
	answer, err := from.Hear(from.PadlockSecret(), reply)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Seq != seq {
		t.Fatalf("the answer names ask %d, not %d", answer.Seq, seq)
	}
	return answer
}

// TestAnAskAndItsAnswerRideOneLine holds the whole of the carriage's ordinary
// day: the listening half has a road to give, an ask goes down one socket and
// its answer comes back up it, and a second ask rides the same connection.
func TestAnAskAndItsAnswerRideOneLine(t *testing.T) {
	h := listening(t, 1<<20)

	// The listening half is the one that knows where it ended up, so it is the
	// one that has a road — and the road is a line's and nothing else's.
	if !strings.HasPrefix(h.listener.Hint, "tcp://127.0.0.1:") {
		t.Fatalf("the listener published %q", h.listener.Hint)
	}
	if strings.HasSuffix(h.listener.Hint, ":0") {
		t.Fatal("the listener published the port it asked for, not the one it got")
	}

	guest, l := visiting(t, h)
	mine := secret("guestHeir")
	base := warden.Reach{Far: h.warden.Name(), Allowance: envelope.Allowance{Time: 5000, Hops: 8}}

	rotate := base
	rotate.NextHeir = &mine
	if first := ask(t, guest, l, rotate); first.Seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d, want 1", first.Seq)
	}

	call := base
	call.Being = &h.being
	call.Method = &envelope.Method{Name: "add", Args: text("milk")}
	if second := ask(t, guest, l, call); second.Seq != 2 {
		t.Fatalf("the second ask spent %d, want 2", second.Seq)
	}
	if len(h.object.items) != 1 || h.object.items[0] != "milk" {
		t.Fatalf("the being holds %v", h.object.items)
	}
	if !l.Open() {
		t.Fatal("the line did not survive its own work")
	}
}

// TestAPushRidesBackDownADialledLine holds the asymmetry the carriage exists
// for: the dialling ground publishes no road at all, and the listener asks
// down a connection it never opened.
func TestAPushRidesBackDownADialledLine(t *testing.T) {
	h := listening(t, 1<<20)
	guest := stand(t, "guest", 1<<20)

	// The dialling ground holds a being of its own and has no road to give:
	// it is reachable only down the lines it holds.
	mine := &todo{}
	being, err := guest.Hold(todoText, mine, warden.Keys{Secret: secret("guestBeing"), HeirSecret: secret("guestBeingHeir")})
	if err != nil {
		t.Fatal(err)
	}
	// The invitation it grants carries no hint, because the road is the line
	// that is about to be open.
	inv, err := guest.Grant(being,
		warden.Keys{Secret: secret("hostVoice"), HeirSecret: secret("hostVoiceHeir")},
		guest.Padlock(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Hints) != 0 {
		t.Fatalf("the dialling ground gave a road: %v", inv.Hints)
	}
	h.warden.Stand(h.warden.Self(), inv, inv.HeirSecret)

	if _, err := line.Dial(door(guest, "guest"), h.listener.Hint); err != nil {
		t.Fatal(err)
	}

	var accepted *line.Line
	select {
	case accepted = <-h.accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the listener never took the line")
	}

	next := secret("hostHeir")
	answer := ask(t, h.warden, accepted, warden.Reach{
		Far:       guest.Name(),
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		// The holder's first act is a rotation, on this carriage as on any
		// other: what travelled was an heir, and it is spent by being used.
		NextHeir: &next,
		Being:    &being,
		Method:   &envelope.Method{Name: "add", Args: text("bread")},
	})
	if answer.Warden != guest.Name() {
		t.Fatal("the door that answered is not the door that was asked")
	}
	if len(mine.items) != 1 || mine.items[0] != "bread" {
		t.Fatalf("the being holds %v", mine.items)
	}
}

// TestARefusedAskProducesNoFrame holds the first of the two failures: a
// well-framed envelope that fails judgment is ordinary silence, which has no
// wire form here, and the line lives on to answer a later legal ask.
func TestARefusedAskProducesNoFrame(t *testing.T) {
	h := listening(t, 1<<20)
	guest, l := visiting(t, h)

	// A legal ask first, so nothing is left awaiting under its number: an ask
	// whose answer would be indistinguishable from one already awaiting is
	// refused by this end's own kit, which the case below would otherwise meet
	// instead of the door's silence.
	next := secret("guestHeir")
	if first := ask(t, guest, l, warden.Reach{
		Far:       h.warden.Name(),
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
	}); first.Seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d, want 1", first.Seq)
	}

	// A voice in neither record, at a being it does not reach.
	if _, came := waited(l.Carry(stranger(t, h.warden, h.being), &line.Expect{Warden: h.warden.Name(), Seq: 1})); came {
		t.Fatal("a refused ask was answered")
	}
	if !l.Open() {
		t.Fatal("a refusal dropped the line")
	}

	// Bytes that are no box at all are the same ordinary silence.
	if _, came := waited(l.Carry([]byte("not a box at all, but well framed"), &line.Expect{Warden: h.warden.Name(), Seq: 99})); came {
		t.Fatal("noise was answered")
	}
	if !l.Open() {
		t.Fatal("noise dropped the line")
	}

	// And a later, legal ask down the same line still answers.
	if later := ask(t, guest, l, warden.Reach{
		Far:       h.warden.Name(),
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}); later.Seq != 2 {
		t.Fatalf("the later ask spent %d, want 2", later.Seq)
	}
}

// TestAnIndistinguishableSecondAskIsNotSent holds the collision rule: two
// voices, one return padlock, one far warden and one number would make two
// answers indistinguishable, so the sender's own kit refuses to send the
// second while the first waits.
func TestAnIndistinguishableSecondAskIsNotSent(t *testing.T) {
	h := listening(t, 1<<20)
	_, l := visiting(t, h)

	want := &line.Expect{Warden: h.warden.Name(), Seq: 1}
	// A voice that stands nowhere, so nothing ever answers and the first ask
	// stays awaiting.
	waiting := l.Carry(stranger(t, h.warden, h.being), want)
	second := l.Carry(stranger(t, h.warden, h.being), want)

	// The second is refused where it stands, and answers the same nothing
	// everything else does.
	reply, came := waited(second)
	if !came || reply != nil {
		t.Fatal("the colliding ask was carried")
	}
	// The first is still waiting, and the line is still carrying.
	if _, came := waited(waiting); came {
		t.Fatal("the refused ask was answered")
	}
	if !l.Open() {
		t.Fatal("refusing the second ask dropped the line")
	}
	// A different number collides with nothing.
	if reply, came := waited(l.Carry(stranger(t, h.warden, h.being), &line.Expect{Warden: h.warden.Name(), Seq: 2})); came && reply != nil {
		t.Fatal("a number that collides with nothing was refused")
	}
}

// TestABrokenFrameDropsTheConnection holds the second failure, in every shape
// it comes in: a peer that cannot frame cannot be spoken to, and is not told
// why.
func TestABrokenFrameDropsTheConnection(t *testing.T) {
	h := listening(t, 1<<20)

	// A negative length. Eight signed bytes can say it, and it means nothing.
	negative := raw(t, h.listener.Hint)
	if _, err := negative.Write(header(-1)); err != nil {
		t.Fatal(err)
	}
	dropped(t, negative)

	// A zero-length frame is malformed, not silence: silence has no wire form
	// here, so an empty frame is a peer that cannot frame.
	empty := raw(t, h.listener.Hint)
	if _, err := empty.Write(header(0)); err != nil {
		t.Fatal(err)
	}
	dropped(t, empty)

	// Over the cap, which the kit takes from the warden's published limit.
	huge := raw(t, h.listener.Hint)
	if _, err := huge.Write(header(h.warden.Limit() + 1)); err != nil {
		t.Fatal(err)
	}
	dropped(t, huge)

	// A body cut short: the length claims more than ever arrives, and the peer
	// stops speaking.
	short := raw(t, h.listener.Hint)
	if _, err := short.Write(append(header(64), make([]byte, 10)...)); err != nil {
		t.Fatal(err)
	}
	if err := short.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	dropped(t, short)
}

// TestABareHintPromisesTheDefault holds the law's number: a road that declares
// nothing promises 16,384 bytes, an envelope of exactly that rides it, and one
// byte more is the framing fault that ends the connection.
func TestABareHintPromisesTheDefault(t *testing.T) {
	h := listening(t, line.DEFAULT)
	if strings.Contains(h.listener.Hint, "?") {
		t.Fatalf("a door at the default declared a cap: %q", h.listener.Hint)
	}

	over := raw(t, h.listener.Hint)
	if _, err := over.Write(header(line.DEFAULT + 1)); err != nil {
		t.Fatal(err)
	}
	dropped(t, over)

	// At the cap the frame is read, and what it holds is no box at all — which
	// is ordinary silence, and the line lives.
	under := raw(t, h.listener.Hint)
	if _, err := under.Write(append(header(line.DEFAULT), make([]byte, line.DEFAULT)...)); err != nil {
		t.Fatal(err)
	}
	_ = under.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := under.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a frame at the default was answered or dropped: %v", err)
	}
}

// TestAClosedLineResolvesItsPendingAsks holds that closing is the same nothing
// a shut door gives, and that a dead line stays dead.
func TestAClosedLineResolvesItsPendingAsks(t *testing.T) {
	h := listening(t, 1<<20)
	_, l := visiting(t, h)

	waiting := l.Carry(stranger(t, h.warden, h.being), &line.Expect{Warden: h.warden.Name(), Seq: 1})
	l.Close()
	if reply, came := waited(waiting); !came || reply != nil {
		t.Fatal("a closed line left its pending ask hanging")
	}
	if l.Open() {
		t.Fatal("a closed line is still open")
	}
	if reply, came := waited(l.Carry(stranger(t, h.warden, h.being), &line.Expect{Warden: h.warden.Name(), Seq: 2})); !came || reply != nil {
		t.Fatal("a dead line took an ask")
	}
}

// TestARetractedRoadStopsCarrying holds that closing the listening half takes
// every line it accepted with it, and the far end's pending ask resolves to the
// same nothing.
func TestARetractedRoadStopsCarrying(t *testing.T) {
	h := listening(t, 1<<20)
	_, l := visiting(t, h)

	waiting := l.Carry(stranger(t, h.warden, h.being), &line.Expect{Warden: h.warden.Name(), Seq: 1})
	if err := h.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if reply, came := waited(waiting); !came || reply != nil {
		t.Fatal("a line whose road stopped carrying left its ask hanging")
	}
}

// TestADoorUnderTheDefaultDialsNoLine holds the one refusal the law still
// keeps: the dialling half publishes no road, so it has nowhere to declare a
// smaller cap and must promise the default. A listener has a road, so the same
// small door stands one — and says its number on it.
func TestADoorUnderTheDefaultDialsNoLine(t *testing.T) {
	h := listening(t, 1<<20)
	small := line.Door{Judge: func([]byte) []byte { return nil }, Limit: line.DEFAULT - 1}

	if _, err := line.Dial(small, h.listener.Hint); !errors.Is(err, line.ErrUnderTheDefault) {
		t.Fatalf("a door under the default dialled a line: %v", err)
	}

	ears, err := line.Listen(small, "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("a door that declares its small cap was refused: %v", err)
	}
	defer func() { _ = ears.Close() }()
	if !strings.HasSuffix(ears.Hint, "?cap=16383") {
		t.Fatalf("a small door published %q", ears.Hint)
	}

	// One byte lower than the default is under it; the default itself is not.
	at := line.Door{Judge: func([]byte) []byte { return nil }, Limit: line.DEFAULT}
	if _, err := line.Dial(at, h.listener.Hint); err != nil {
		t.Fatalf("a door at the default was refused: %v", err)
	}
}

// TestADeclaredCapBoundsWhatTheDialerSends holds the road describing itself: a
// door with a small appetite says so in its hint, and the dialler that read it
// refuses the over-cap envelope in its own kit rather than sending a frame that
// would kill the line.
func TestADeclaredCapBoundsWhatTheDialerSends(t *testing.T) {
	h := listening(t, 4096)
	if !strings.HasSuffix(h.listener.Hint, "?cap=4096") {
		t.Fatalf("a small door published %q", h.listener.Hint)
	}

	guest, l := visiting(t, h)
	if reply, came := waited(l.Carry(make([]byte, 5000), nil)); !came || reply != nil {
		t.Fatal("an envelope over the far cap was not refused at once")
	}
	if !l.Open() {
		t.Fatal("refusing to send killed the line")
	}

	// And the line is still the ordinary line: an envelope under the declared
	// cap rides it and its answer comes back. Whoever minted a voice has seen
	// its keys, so the first ask down it is a rotate-and-ask.
	mine := secret("guestHeir")
	rotate := warden.Reach{Far: h.warden.Name(), Allowance: envelope.Allowance{Time: 5000, Hops: 8}, NextHeir: &mine}
	if first := ask(t, guest, l, rotate); first.Seq != 1 {
		t.Fatalf("the rotate-and-ask spent %d, want 1", first.Seq)
	}
	call := warden.Reach{
		Far:       h.warden.Name(),
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Being:     &h.being,
		Method:    &envelope.Method{Name: "add", Args: text("milk")},
	}
	if second := ask(t, guest, l, call); second.Seq != 2 {
		t.Fatalf("the ask under the cap spent %d, want 2", second.Seq)
	}
	if len(h.object.items) != 1 {
		t.Fatalf("the being holds %v", h.object.items)
	}
}

// TestAWardenWithNoLimitDeclaresTheKitsCap holds the other side of the hint: a
// door whose appetite is not the default says the number on its road, and a
// frame of the default size still rides it.
func TestAWardenWithNoLimitDeclaresTheKitsCap(t *testing.T) {
	h := listening(t, 0)
	if h.warden.Limit() != 0 {
		t.Fatalf("the house published a limit of %d", h.warden.Limit())
	}
	if !strings.HasSuffix(h.listener.Hint, "?cap=1048576") {
		t.Fatalf("a roomy door published %q", h.listener.Hint)
	}

	// The body is no box at all, so what comes of it is ordinary silence —
	// which is the proof the frame was read rather than the peer dropped.
	conn := raw(t, h.listener.Hint)
	if _, err := conn.Write(append(header(line.DEFAULT), make([]byte, line.DEFAULT)...)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a frame at the default was answered or dropped: %v", err)
	}
}

// TestAHintThatIsNotALineIsNotDialled holds the scheme to tcp://host:port with
// at most a ?cap= of decimal bytes after it: no second scheme, no path, no bare
// address, and no cap that is not a plain number.
func TestAHintThatIsNotALineIsNotDialled(t *testing.T) {
	h := listening(t, 1<<20)
	guest := stand(t, "guest", 1<<20)
	at, _, _ := strings.Cut(strings.TrimPrefix(h.listener.Hint, "tcp://"), "?")

	for _, hint := range []string{
		"http://" + at,
		"tcp://" + at + "/path",
		at,
		"tcp://127.0.0.1",
		"tcp://127.0.0.1:notaport",
		"tcp://" + at + "?cap=",
		"tcp://" + at + "?cap=big",
		"tcp://" + at + "?cap=16384x",
		"tcp://" + at + "?cap=16384&x=1",
		"tcp://" + at + "?cap=0",
		"tcp://" + at + "?limit=16384",
		// A cap of zero or a port of zero names a door that can take nothing,
		// and is no road at all.
		"tcp://127.0.0.1:0",
		"tcp://127.0.0.1:0?cap=16384",
	} {
		if _, err := line.Dial(door(guest, "guest"), hint); !errors.Is(err, line.ErrNotALine) {
			t.Fatalf("%q was taken for a line: %v", hint, err)
		}
	}
}

// TestTheDiallingEndAcceptsTheDefaultAndNoMore holds the law's plainest words
// about the two ends: an end that publishes nothing promises the default, and
// there is no way to promise more. So what a dialler accepts on an arriving
// frame is the default exactly, whatever its own appetite — this one's is
// sixty-four times larger.
func TestTheDiallingEndAcceptsTheDefaultAndNoMore(t *testing.T) {
	guest := stand(t, "guest", 1<<20)

	// The far half is plain TCP, because what is being asserted is framing
	// rather than judgment: this end writes the frames by hand.
	ears, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ears.Close() }()
	conns := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := ears.Accept()
			if err != nil {
				return
			}
			conns <- conn
		}
	}()

	hint := "tcp://" + ears.Addr().String()
	// The header alone is what the cap is judged on, before anything says what
	// the frame carries; a body written after it would only race the drop.
	frame := func(n int64, body bool) net.Conn {
		t.Helper()
		l, err := line.Dial(door(guest, "guest"), hint)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(l.Close)
		conn := <-conns
		t.Cleanup(func() { _ = conn.Close() })
		out := header(n)
		if body {
			out = append(out, make([]byte, n)...)
		}
		if _, err := conn.Write(out); err != nil {
			t.Fatal(err)
		}
		return conn
	}

	// One byte over the default and the dialler drops without a word, though
	// its own door would have taken a megabyte.
	dropped(t, frame(line.DEFAULT+1, false))

	// At the default the frame is read, and what it holds is no box at all —
	// ordinary silence, and the line lives.
	at := frame(line.DEFAULT, true)
	_ = at.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := at.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a frame at the default was answered or dropped: %v", err)
	}
}

// TestADeclaredCapIsAFloor holds the other half of a published cap: a door may
// accept more than it promised, never less. The boundary is the number on the
// road, byte for byte — at it the frame is read, one over it the peer that
// cannot frame is dropped without a word.
func TestADeclaredCapIsAFloor(t *testing.T) {
	h := listening(t, 4096)
	if !strings.HasSuffix(h.listener.Hint, "?cap=4096") {
		t.Fatalf("a small door published %q", h.listener.Hint)
	}

	at := raw(t, h.listener.Hint)
	if _, err := at.Write(append(header(4096), make([]byte, 4096)...)); err != nil {
		t.Fatal(err)
	}
	_ = at.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := at.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a frame at the declared cap was answered or dropped: %v", err)
	}

	over := raw(t, h.listener.Hint)
	if _, err := over.Write(header(4097)); err != nil {
		t.Fatal(err)
	}
	dropped(t, over)
}

// TestADeadRoadIsWeatherRatherThanSilence holds the distinction the law draws
// in words: a road that never carried the bytes — a connection refused, a name
// that does not resolve — said neither an answer nor silence, and a kit reports
// it as the road's fault rather than inventing an empty body.
func TestADeadRoadIsWeatherRatherThanSilence(t *testing.T) {
	guest := stand(t, "guest", 1<<20)

	// A port nobody is listening on: the address is well formed, so the hint is
	// a line, and what fails is the weather.
	ears, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := ears.Addr().String()
	if err := ears.Close(); err != nil {
		t.Fatal(err)
	}
	if l, err := line.Dial(door(guest, "guest"), "tcp://"+at); err == nil {
		l.Close()
		t.Fatal("a dead road opened a line")
	} else if errors.Is(err, line.ErrNotALine) {
		t.Fatal("weather was reported as a malformed hint")
	}

	// And a name that does not resolve is the same weather, told apart from a
	// hint this carriage does not speak.
	if l, err := line.Dial(door(guest, "guest"), "tcp://no.such.host.invalid:9"); err == nil {
		l.Close()
		t.Fatal("an unresolvable name opened a line")
	} else if errors.Is(err, line.ErrNotALine) {
		t.Fatal("weather was reported as a malformed hint")
	}
}

// TestACallerTakesTheRoadItCanSpeak holds the caller's whole job: a warden
// offers as many roads as it has, and the caller takes the first one it can
// speak that carried. Nothing at the call site says which, and nothing was
// configured — in Go the answer is settled at build time, by whether the
// program imports this package at all.
func TestACallerTakesTheRoadItCanSpeak(t *testing.T) {
	h := listening(t, 1<<20)

	// The house stands on both roads at once and ranks neither: it offers what
	// it has and the caller chooses.
	carriageDoor := carriage.Handler(h.warden.Limit(), door(h.warden, "house").Judge)
	served := httptest.NewServer(carriageDoor)
	t.Cleanup(served.Close)
	hints := []string{h.listener.Hint, served.URL}

	inv, err := h.warden.Grant(h.being,
		warden.Keys{Secret: secret("bothVoice"), HeirSecret: secret("bothVoiceHeir")},
		h.warden.Padlock(), hints)
	if err != nil {
		t.Fatal(err)
	}
	guest := stand(t, "guest", 1<<20)
	guest.Stand(guest.Self(), inv, inv.HeirSecret)

	// A caller holding a door has sockets under it, so it takes the tcp:// hint
	// the house offered first — never told to, never asked.
	mine := secret("bothHeir")
	speaking := &line.Caller{Door: door(guest, "guest")}
	t.Cleanup(speaking.HangUp)
	message, seq, err := guest.Ask(secret("askEphemeral"), warden.Reach{
		Far:       h.warden.Name(),
		NextHeir:  &mine,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := speaking.Send(hints, message, &line.Expect{Warden: h.warden.Name(), Seq: seq})
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil {
		t.Fatal("nothing came back")
	}
	if _, err := guest.Hear(guest.PadlockSecret(), reply); err != nil {
		t.Fatal(err)
	}
	if len(h.listener.Lines()) != 1 {
		t.Fatalf("the ask went down %d lines, want one", len(h.listener.Lines()))
	}

	// The same caller with no door cannot hold a line, so the tcp:// hint is a
	// road it cannot speak. It walks past and posts, and no second connection
	// was opened. The road was never the point: the seal is what proved it.
	posting := &line.Caller{}
	next := secret("bothHeirNext")
	message, seq, err = guest.Ask(secret("askEphemeral2"), warden.Reach{
		Far:       h.warden.Name(),
		NextHeir:  &next,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	reply, err = posting.Send(hints, message, &line.Expect{Warden: h.warden.Name(), Seq: seq})
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil {
		t.Fatal("the carriage carried nothing")
	}
	if _, err := guest.Hear(guest.PadlockSecret(), reply); err != nil {
		t.Fatal(err)
	}
	if len(h.listener.Lines()) != 1 {
		t.Fatalf("a caller with no door opened %d lines", len(h.listener.Lines()))
	}
}

// TestARoadTheCallerCannotSpeakIsNotARoadThatFailed holds the difference
// between the three nothings. Nothing was sent down a road this caller cannot
// speak, so no door spoke and no road broke: it is neither silence nor weather,
// and it is never the fault reported at the end.
func TestARoadTheCallerCannotSpeakIsNotARoadThatFailed(t *testing.T) {
	posting := &line.Caller{}

	// One road it cannot speak and one that is weather: what comes back is the
	// weather, never the skip.
	if _, err := posting.Send([]string{"tcp://127.0.0.1:9", "http://127.0.0.1:1/"},
		[]byte("hello"), nil); err == nil {
		t.Fatal("a dead road carried")
	}

	// And a list of nothing but roads it cannot speak is no road tried at all,
	// which is not weather either: there is no fault to report the road of.
	reply, err := posting.Send([]string{"tcp://127.0.0.1:9"}, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("skipping every road was reported as weather: %v", err)
	}
	if reply != nil {
		t.Fatal("a road nobody spoke carried bytes")
	}
}
