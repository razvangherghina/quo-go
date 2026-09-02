// Package line is the second carriage: sealed envelopes as length-prefixed
// frames over one persistent TCP connection. It is for the roads where both
// ends are consenting grounds — droplet to droplet, same machine, a held line —
// where TLS and HTTP buy nothing, because the envelope already carries all the
// crypto. Article III names it, which makes it standard and never mandatory:
// the common carriage stays the one road every warden answers, because a
// browser tab can open no socket and reach outranks fit.
//
// A frame is a length written the way the wire encoding writes an `int` — eight
// bytes, signed two's complement, most significant first — and then that many
// envelope bytes. That is the frame's whole vocabulary. There is no direction
// bit, no correlation id, no header and no negotiation, because anything
// outside the seal that carried meaning would be meaning outside the seal.
//
// Silence has no wire form here. HTTP forces a response and so the common
// carriage needs an empty body for it; a persistent line does not. A refused or
// unresolvable ask simply produces no frame, and the caller's own deadline is
// its own affair. A zero-length frame is therefore malformed, not silence.
//
// Two failures, two consequences. A well-framed envelope that fails judgment is
// ordinary silence and the line lives on. A broken frame — negative length,
// zero length, a length over the cap, a body cut short — drops the connection
// without a word, because a peer that cannot frame cannot be spoken to.
//
// It sits beside carriage rather than inside it because the two disagree about
// how silence rides, and a package holding both doctrines would no longer
// explain either.
package line

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// length is the frame header: eight bytes, the way Article V writes an int.
const length = 8

// CAP is the frame cap this kit uses where the host published no limit. Eight
// signed bytes can claim an exabyte, so a line that read whatever the length
// claimed would be a line anyone can exhaust. The number is the kit's, never
// the law's.
const CAP int64 = 1 << 20

// DEFAULT is the law's number rather than the kit's: a bare tcp:// hint
// promises that this end accepts envelopes to 16,384 bytes, and the dialling
// end — which publishes nothing — always promises exactly this. A door with
// another appetite says so in the hint it publishes.
const DEFAULT int64 = 16384

// ErrUnderTheDefault is what a door holding less than the default gets when it
// tries to dial. The dialling half publishes no road, so it has nowhere to
// declare a smaller cap and therefore does not offer the line. It comes back at
// the open, because such an end never had a line to fail on mid-frame.
var ErrUnderTheDefault = errors.New("line: a door under the default declares no cap and offers no line")

// Door is where a line hands every frame it reads. A line never opens a seal:
// it cannot tell an ask from an answer, does not want to, and holds no secret
// with which it could find out. It hands the bytes to the warden's one entry
// point and writes back whatever bytes come.
type Door struct {
	// Arrive is the warden's one entry point. The bytes that arrived go in
	// beside the line they arrived on — an opaque token the warden never reads
	// and hands straight back to delivery — and the sealed answer, or nothing,
	// comes out. Nothing comes out for an answer, because an answer settles the
	// ask awaiting it inside.
	Arrive func(message []byte, via any) []byte

	// Limit is the frame cap this end accepts: the number the host gave, else
	// CAP. Zero or less takes CAP. A listener declares whatever it resolves in
	// the road it publishes, so any size stands there; a dialler publishes
	// nothing and so cannot hold less than DEFAULT.
	Limit int64
}

func (d Door) cap() int64 {
	if d.Limit > 0 {
		return d.Limit
	}
	return CAP
}

// promise refuses a door that publishes no road and cannot accept an envelope
// of the default size.
func (d Door) promise() error {
	if d.cap() < DEFAULT {
		return ErrUnderTheDefault
	}
	return nil
}

// Line is one live connection, from either end: the two halves differ only in
// who dialled. Frames flow both ways on it, so both ends can originate asks
// down one connection.
type Line struct {
	conn net.Conn
	door Door
	// far is the cap the road at the other end promised — the default wherever
	// nothing was declared, which is the dialling half always.
	far int64
	// near is what this end accepts on an arriving frame. A listener accepts
	// what its published road declared; a dialler publishes nothing, so it has
	// no way to promise more than the default and accepts exactly that,
	// whatever its own appetite.
	near int64

	mu      sync.Mutex
	writing sync.Mutex
	alive   bool
	once    sync.Once
	closed  []func()
}

func hold(conn net.Conn, door Door, far, near int64) *Line {
	l := &Line{conn: conn, door: door, far: far, near: near, alive: true}
	go l.read()
	return l
}

// OnClose registers what to do when this line stops carrying, so whoever keeps
// a table of lines can let go of a dead one.
func (l *Line) OnClose(fn func()) {
	l.mu.Lock()
	if !l.alive {
		l.mu.Unlock()
		fn()
		return
	}
	l.closed = append(l.closed, fn)
	l.mu.Unlock()
}

// Open says whether the line is still carrying. The line is dumb: no reconnect,
// no keep-alive, no health probe, and re-dialling is the caller's affair the
// way trying another hint already is.
func (l *Line) Open() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.alive
}

// Close shuts the line down. Whoever was waiting on an answer that would have
// come down it waits out its own deadline, which is the same nothing a shut
// door gives.
func (l *Line) Close() { l.shut() }

func (l *Line) shut() {
	l.once.Do(func() {
		l.mu.Lock()
		l.alive = false
		told := l.closed
		l.closed = nil
		l.mu.Unlock()
		_ = l.conn.Close()
		for _, fn := range told {
			fn()
		}
	})
}

// Carry sends one envelope down the line and says whether it went. Nothing
// comes back here: an answer arrives as a frame of its own and goes in the
// warden's one entry point like everything else, which is what pairs it with
// the ask awaiting it.
func (l *Line) Carry(message []byte) bool {
	l.mu.Lock()
	alive := l.alive
	l.mu.Unlock()
	if !alive {
		return false
	}
	// Over what the far road promised is refused here, before a byte flows:
	// sending it would have the far end drop the connection without a word, and
	// killing your own line is worse than not sending.
	if int64(len(message)) > l.far {
		return false
	}
	if err := l.write(message); err != nil {
		l.shut()
		return false
	}
	return true
}

// write is the one place bytes leave, and it is serialised: both ends may
// originate on one connection and an answer is written by whichever goroutine
// judged it, so two half-written frames would be one unreadable line.
func (l *Line) write(message []byte) error {
	l.writing.Lock()
	defer l.writing.Unlock()
	frame := make([]byte, length+len(message))
	binary.BigEndian.PutUint64(frame[:length], uint64(len(message)))
	copy(frame[length:], message)
	_, err := l.conn.Write(frame)
	return err
}

// read is the whole of what arrives. A broken frame — negative, zero, over the
// cap, or a body cut short — drops the connection without a word, because a
// peer that cannot frame cannot be spoken to.
func (l *Line) read() {
	defer l.shut()
	header := make([]byte, length)
	for {
		if _, err := io.ReadFull(l.conn, header); err != nil {
			return
		}
		claimed := int64(binary.BigEndian.Uint64(header))
		if claimed <= 0 || claimed > l.near {
			return
		}
		body := make([]byte, claimed)
		if _, err := io.ReadFull(l.conn, body); err != nil {
			return
		}
		l.arrive(body)
	}
}

// arrive hands one frame to the door and writes back whatever bytes come. The
// line reads nothing: which of the two records arrived is inside the seal, and
// the only thing holding the secret that opens it is the warden.
//
// It runs on its own goroutine, because judging a frame may itself wait for an
// answer that arrives on this same line — a being in the middle of a chain — and
// a pump that waited on a judgment would be a pump that deadlocks on its own
// connection.
func (l *Line) arrive(message []byte) {
	if l.door.Arrive == nil {
		return
	}
	go func() {
		back := l.door.Arrive(message, l)
		if len(back) == 0 {
			return
		}
		// An answer over what the far road promised is not sent at all: silence
		// keeps the line, and a frame the far end must drop does not.
		if int64(len(back)) > l.far {
			return
		}
		if err := l.write(back); err != nil {
			l.shut()
		}
	}()
}

// ErrNotALine is what a hint that is no line gets. The scheme is
// tcp://host:port, optionally followed by ?cap= and the door's cap in decimal
// bytes, and nothing after that: no path, no second query, no second scheme.
var ErrNotALine = errors.New("line: that hint is not a line")

// road splits a hint into the address to dial and the cap the far door
// promised. A bare road promises the default.
func road(hint string) (string, int64, error) {
	rest, ok := strings.CutPrefix(hint, "tcp://")
	if !ok || strings.ContainsAny(rest, "/#") {
		return "", 0, ErrNotALine
	}
	far := DEFAULT
	if at, declared, found := strings.Cut(rest, "?"); found {
		digits, ok := strings.CutPrefix(declared, "cap=")
		if !ok {
			return "", 0, ErrNotALine
		}
		// Decimal bytes and nothing else: no sign, no spaces, no second query.
		for _, b := range []byte(digits) {
			if b < '0' || b > '9' {
				return "", 0, ErrNotALine
			}
		}
		size, err := strconv.ParseInt(digits, 10, 64)
		if err != nil || size <= 0 {
			return "", 0, ErrNotALine
		}
		rest, far = at, size
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil || host == "" {
		return "", 0, ErrNotALine
	}
	// A hint declaring a cap of zero or a port of zero names a door that can
	// take nothing, and is no road at all.
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "", 0, ErrNotALine
	}
	return rest, far, nil
}

// Dial opens a line to a tcp://host:port hint, reading the cap the road
// declares before connecting. The dialling half publishes nothing: it is
// reachable only down the lines it holds, and so it promises the default.
func Dial(door Door, hint string) (*Line, error) {
	if err := door.promise(); err != nil {
		return nil, err
	}
	at, far, err := road(hint)
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", at)
	if err != nil {
		return nil, err
	}
	// This half publishes nothing and so promises the default, and there is no
	// way to promise more: what it accepts is the default exactly.
	return hold(conn, door, far, DEFAULT), nil
}

// Listener is the listening half. It is the one that knows where it ended up,
// so it is the one that has a road to give: Hint is what its host grants and
// cards with, exactly as the URL of an HTTP door is.
type Listener struct {
	Hint string

	listener net.Listener
	accepted func(*Line)

	mu    sync.Mutex
	lines map[*Line]bool
	open  bool
}

// Listen stands a door on a TCP address — "127.0.0.1:0" for an ephemeral port.
// Each accepted line is handed to accepted, when there is one, for a ground
// that means to push down a connection somebody else opened.
func Listen(door Door, address string, accepted func(*Line)) (*Listener, error) {
	raw, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	at := raw.Addr().(*net.TCPAddr)
	host := at.IP.String()
	// The road says the cap before a byte flows. A bare road is the promise of
	// the default, so only a door with another appetite writes the query.
	declared := ""
	if door.cap() != DEFAULT {
		declared = "?cap=" + strconv.FormatInt(door.cap(), 10)
	}
	s := &Listener{
		Hint:     "tcp://" + net.JoinHostPort(host, strconv.Itoa(at.Port)) + declared,
		listener: raw,
		accepted: accepted,
		lines:    map[*Line]bool{},
		open:     true,
	}
	go s.serve(door)
	return s, nil
}

func (s *Listener) serve(door Door) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		// Whoever dialled published nothing, so what this end may send down an
		// accepted line is the default and only the default.
		l := hold(conn, door, DEFAULT, door.cap())
		s.mu.Lock()
		if !s.open {
			s.mu.Unlock()
			l.Close()
			return
		}
		s.lines[l] = true
		s.mu.Unlock()
		if s.accepted != nil {
			s.accepted(l)
		}
	}
}

// Lines is every line this listener currently holds.
func (s *Listener) Lines() []*Line {
	s.mu.Lock()
	defer s.mu.Unlock()
	held := make([]*Line, 0, len(s.lines))
	for l := range s.lines {
		held = append(held, l)
	}
	return held
}

// Close stops listening and shuts every line it accepted, whose pending asks
// resolve to nothing. A road that has stopped carrying is not a road.
func (s *Listener) Close() error {
	s.mu.Lock()
	s.open = false
	held := make([]*Line, 0, len(s.lines))
	for l := range s.lines {
		held = append(held, l)
	}
	s.lines = map[*Line]bool{}
	s.mu.Unlock()
	for _, l := range held {
		l.Close()
	}
	return s.listener.Close()
}

// Speaks says whether a hint names a road this package can carry. Choosing
// among a peer's hints is delivery's job, and this is the one fact about a hint
// that a line has to offer it.
func Speaks(hint string) bool { return strings.HasPrefix(hint, "tcp://") }
