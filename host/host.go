// Package host is the third part of papers/quo-truth.md: what the host does.
// It opens a warden on the seeds, the clock, the randomness and the store it is
// handed, stands roads in front of the warden's one entry point, and is
// delivery beneath it.
//
// This is the only package in the kit that knows every road by name, and it
// holds no secret of its own: what it keeps per peer is an address — a padlock,
// which is a public key — beside the line that peer's asks arrive on.
//
// Delivery has three rules and no more. A row with hints: the first road this
// ground can speak that carried. A row without hints, or none it can speak: the
// line that padlock's last ask arrived on, if still held. Neither: weather, and
// the number was spent.
package host

import (
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
	"quo.systems/kit/line"
	"quo.systems/kit/warden"
)

// Roads a host can stand. Which of them a ground stands is the host's own
// choice; a ground that stands none is the tab's case, reachable only down the
// lines it dials.
const (
	// HTTP is the common carriage, the one road every warden answers.
	HTTP = "http"
	// Line is the framed TCP carriage, for the roads where both ends are
	// consenting grounds.
	Line = "line"
	// InProcess is the road of distance zero: bytes handed straight to another
	// warden in this process, with no step waived.
	InProcess = "memory"
)

// grounds are the in-process doors, kept process-wide so two hosts opened in
// one bench find each other the way two wardens in one device would.
var grounds sync.Map // hint -> *warden.Warden

// Seeds are the three draws a ground is founded on. A zero Seeds is drawn from
// the host's own randomness.
type Seeds struct {
	Name    [32]byte
	Padlock [32]byte
	Heir    [32]byte
}

// Standing is what a host is opened with.
type Standing struct {
	Seeds Seeds
	// Clock reads the host's clock in milliseconds. Nil takes the wall clock.
	Clock func() int64
	// Random is the host's randomness. Nil takes crypto/rand.
	Random func() [32]byte
	// Store is where the warden's records live. Nil takes a memory store.
	Store warden.Store
	// Roads are the roads to stand, by the names above.
	Roads []string
	// Listen is where a road with a socket binds. Empty takes an ephemeral
	// loopback port.
	Listen string
	// Hints are roads this ground already knows it answers on, beside whatever
	// the roads it stands publish for themselves.
	Hints []string
	// Limit is what this door will take, the one fact the law makes a warden
	// publish.
	Limit int64
	// Allowance is what a walk started here is born with.
	Allowance envelope.Allowance
}

// Host is a warden, the roads standing in front of it, and delivery beneath.
type Host struct {
	Warden *warden.Warden

	limit int64
	clock func() int64

	mu sync.Mutex
	// byPadlock is the association between an accepted line and the padlock
	// whose asks arrive on it, refreshed on every frame, so a push can find its
	// way back to a peer that publishes nothing. The road cannot make this
	// association itself, because the padlock is inside the seal; the warden
	// makes it and hands it down as an address beside an opaque token.
	byPadlock map[[32]byte]*line.Line
	// byHint is the lines this host dialled, one per road, because a line is
	// persistent by definition: a fresh connection per ask would be the common
	// carriage wearing a socket.
	byHint map[string]*line.Line

	stood []func()
}

// Open stands a ground up.
func Open(s Standing) (*Host, error) {
	clock := s.Clock
	if clock == nil {
		clock = func() int64 { return time.Now().UnixMilli() }
	}
	random := s.Random
	if random == nil {
		random = draw
	}
	seeds := s.Seeds
	if seeds.Name == ([32]byte{}) {
		seeds.Name = random()
	}
	if seeds.Padlock == ([32]byte{}) {
		seeds.Padlock = random()
	}
	if seeds.Heir == ([32]byte{}) {
		seeds.Heir = random()
	}
	store := s.Store
	if store == nil {
		store = &warden.MemoryStore{}
	}
	limit := s.Limit
	if limit == 0 {
		limit = 1 << 20
	}

	h := &Host{
		limit:     limit,
		clock:     clock,
		byPadlock: map[[32]byte]*line.Line{},
		byHint:    map[string]*line.Line{},
	}
	w, err := warden.New(warden.Founding{
		NameSecret: seeds.Name,
		// The warden's own heir is the owner's, held outside the runner's
		// reach, so only its commitment is founded here.
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(seeds.Name), arithmetic.SigningKey(seeds.Heir)),
		PadlockSecret:  seeds.Padlock,
		Limit:          limit,
		Clock:          clock,
		Random:         random,
		Delivery:       h,
		Store:          store,
		Allowance:      s.Allowance,
		Hints:          s.Hints,
	})
	if err != nil {
		return nil, err
	}
	h.Warden = w

	for _, road := range s.Roads {
		if err := h.stand(road, s.Listen); err != nil {
			h.Close()
			return nil, err
		}
	}
	return h, nil
}

func (h *Host) stand(road, at string) error {
	if at == "" {
		at = "127.0.0.1:0"
	}
	switch road {
	case InProcess:
		hint := "mem://" + hexOf(h.Warden.Name())
		grounds.Store(hint, h.Warden)
		h.Warden.Publish(hint)
		h.stood = append(h.stood, func() {
			h.Warden.Retract(hint)
			grounds.Delete(hint)
		})
		return nil

	case HTTP:
		ln, err := net.Listen("tcp", at)
		if err != nil {
			return err
		}
		// The hint is the whole address, posted to exactly as given. A door is
		// the only thing that knows where it ended up, so it tells the warden.
		hint := "http://" + ln.Addr().String() + "/"
		server := &http.Server{Handler: carriage.Handler(h.limit, func(message []byte) []byte {
			// The common carriage holds no line, so there is no road token to
			// hand down: an answer rides the response it came in on.
			return h.Warden.Arrive(message, nil)
		})}
		go func() { _ = server.Serve(ln) }()
		h.Warden.Publish(hint)
		h.stood = append(h.stood, func() {
			h.Warden.Retract(hint)
			_ = server.Close()
		})
		return nil

	case Line:
		// Nothing is done with an accepted line at the moment it is accepted: it
		// is the warden, having judged a frame, that says which padlock's asks
		// arrive on it, and until then there is nothing to key it by.
		ears, err := line.Listen(h.door(), at, nil)
		if err != nil {
			return err
		}
		h.Warden.Publish(ears.Hint)
		h.stood = append(h.stood, func() {
			h.Warden.Retract(ears.Hint)
			_ = ears.Close()
		})
		return nil
	}
	return errors.New("host: no road by that name")
}

// door is what every line hands its frames to: the warden's one entry point,
// with the line itself as the opaque token.
func (h *Host) door() line.Door {
	return line.Door{
		Arrive: func(message []byte, via any) []byte { return h.Warden.Arrive(message, via) },
		Limit:  h.limit,
	}
}

// Arrived is the warden's one call downward. The warden, having judged a
// frame, hands the caller's padlock beside the road the frame arrived on. This
// host reads nothing of either: the padlock is an address and the road is a
// token.
func (h *Host) Arrived(padlock [32]byte, via any) {
	l, ok := via.(*line.Line)
	if !ok || l == nil {
		return
	}
	h.mu.Lock()
	h.byPadlock[padlock] = l
	h.mu.Unlock()
	l.OnClose(func() {
		h.mu.Lock()
		if h.byPadlock[padlock] == l {
			delete(h.byPadlock, padlock)
		}
		h.mu.Unlock()
	})
}

// Send is delivery's three rules and no more.
func (h *Host) Send(row warden.Row, message []byte) ([]byte, bool) {
	for _, hint := range row.Hints {
		switch {
		case strings.HasPrefix(hint, "mem://"):
			far, ok := grounds.Load(hint)
			if !ok {
				continue
			}
			return far.(*warden.Warden).Arrive(message, nil), false

		case strings.HasPrefix(hint, "http://"), strings.HasPrefix(hint, "https://"):
			back, err := carriage.Caller{}.Send([]string{hint}, message)
			if err != nil {
				// Weather on this road; the next may carry.
				continue
			}
			return back, false

		case line.Speaks(hint):
			l := h.dial(hint)
			if l == nil {
				continue
			}
			// The answer arrives as a frame of its own, through the door.
			if l.Carry(message) {
				return nil, true
			}
			continue
		}
	}
	// No hints, or none this ground can speak: the line that padlock's last ask
	// arrived on, if still held.
	h.mu.Lock()
	back := h.byPadlock[row.Padlock]
	h.mu.Unlock()
	if back != nil && back.Open() && back.Carry(message) {
		return nil, true
	}
	// Weather, and the number was spent.
	return nil, false
}

func (h *Host) dial(hint string) *line.Line {
	h.mu.Lock()
	held, ok := h.byHint[hint]
	h.mu.Unlock()
	if ok && held.Open() {
		return held
	}
	dialled, err := line.Dial(h.door(), hint)
	if err != nil {
		return nil
	}
	h.mu.Lock()
	h.byHint[hint] = dialled
	h.mu.Unlock()
	dialled.OnClose(func() {
		h.mu.Lock()
		if h.byHint[hint] == dialled {
			delete(h.byHint, hint)
		}
		h.mu.Unlock()
	})
	return dialled
}

// Close takes every road down and lets go of every line this host holds.
func (h *Host) Close() {
	for _, down := range h.stood {
		down()
	}
	h.stood = nil
	h.mu.Lock()
	held := make([]*line.Line, 0, len(h.byHint)+len(h.byPadlock))
	for _, l := range h.byHint {
		held = append(held, l)
	}
	for _, l := range h.byPadlock {
		held = append(held, l)
	}
	h.byHint = map[string]*line.Line{}
	h.byPadlock = map[[32]byte]*line.Line{}
	h.mu.Unlock()
	for _, l := range held {
		l.Close()
	}
}

func draw() [32]byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b
}

const hexits = "0123456789abcdef"

func hexOf(k [32]byte) string {
	out := make([]byte, 64)
	for i, b := range k {
		out[i*2], out[i*2+1] = hexits[b>>4], hexits[b&0xf]
	}
	return string(out)
}
