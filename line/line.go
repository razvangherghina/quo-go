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

	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
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

// Door is what a line hands its arriving frames to. Both halves are the host's
// closures for the same reason the common carriage takes one: a judgment needs
// randomness the host draws, and opening an answer needs a padlock secret,
// neither of which a carriage may reach for.
type Door struct {
	// Judge takes an arriving say and hands back the sealed answer, or nil for
	// silence — which on this carriage produces no frame at all. It is the same
	// door the common carriage answers with.
	Judge carriage.Answer

	// Hear opens an arriving frame as an answer sealed to this end, under the
	// padlock secret the asks from this end named. The error is the ordinary
	// "this was not an answer to me", which is most frames.
	//
	// It tells the two records apart and nothing more, so it is
	// envelope.OpenAnswer and never the warden's own Hear: judging an answer
	// spends the awaiting record the caller keeps for it, and a road that
	// spent it while sorting frames would leave nothing for the caller to
	// judge. The road demultiplexes; the caller judges.
	Hear func(message []byte) (envelope.Answer, error)

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

// Expect names the ask this end wants an answer to: the far warden and the
// number the ask spent. Both are the caller's own knowledge of the message it
// built, and neither ever travels outside a seal.
type Expect struct {
	Warden [32]byte
	Seq    int64
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

	mu sync.Mutex
	// What this end is waiting to hear, keyed by the far warden and the number
	// of the ask.
	pending map[Expect]chan []byte
	alive   bool
	once    sync.Once
}

func hold(conn net.Conn, door Door, far, near int64) *Line {
	l := &Line{conn: conn, door: door, far: far, near: near, pending: map[Expect]chan []byte{}, alive: true}
	go l.read()
	return l
}

// Open says whether the line is still carrying. The line is dumb: no reconnect,
// no keep-alive, no health probe, and re-dialling is the caller's affair the
// way trying another hint already is.
func (l *Line) Open() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.alive
}

// Close shuts the line down. Its pending asks resolve to nothing — the same
// nothing a shut door gives.
func (l *Line) Close() { l.shut() }

func (l *Line) shut() {
	l.once.Do(func() {
		l.mu.Lock()
		l.alive = false
		waiting := l.pending
		l.pending = map[Expect]chan []byte{}
		l.mu.Unlock()
		for _, ch := range waiting {
			ch <- nil
		}
		_ = l.conn.Close()
	})
}

// Carry sends one envelope down the line. Handed an expect, the channel it
// returns receives the answer's sealed bytes, or nil if the line closes first;
// handed none, this is a say and the channel receives nil at once. There is
// always a channel and it always delivers exactly one value, so a caller's own
// deadline is a select of its own.
func (l *Line) Carry(message []byte, expect *Expect) <-chan []byte {
	ch := make(chan []byte, 1)

	l.mu.Lock()
	if !l.alive {
		l.mu.Unlock()
		ch <- nil
		return ch
	}
	// Over what the far road promised is refused here, before a byte flows:
	// sending it would have the far end drop the connection without a word, and
	// killing your own line is worse than not sending.
	if int64(len(message)) > l.far {
		l.mu.Unlock()
		ch <- nil
		return ch
	}
	if expect != nil {
		// One return padlock — this end's own — one far warden and one number
		// would make two answers indistinguishable, so the second ask is not sent
		// while the first waits. Refusing here is the sender's own kit saying no;
		// the ask never reaches the road.
		if _, waiting := l.pending[*expect]; waiting {
			l.mu.Unlock()
			ch <- nil
			return ch
		}
		l.pending[*expect] = ch
	}
	l.mu.Unlock()

	if err := l.write(message); err != nil {
		// A line that has stopped carrying is a dead line, and its pending asks
		// resolve to the same nothing a shut door gives.
		l.shut()
		if expect == nil {
			ch <- nil
		}
		return ch
	}
	if expect == nil {
		ch <- nil
	}
	return ch
}

func (l *Line) write(message []byte) error {
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

// arrive resolves one frame by unsealing and by nothing else, and the record
// byte inside the seal says which of the two it is: Hear refuses anything that
// is not an answer by that byte, so nothing is tried as one record and then as
// the other. An answer to an ask this end is waiting on — opened under the
// padlock that ask named — pairs by the warden and the seq inside the seal.
// Otherwise the envelope is a say, handed to judgment; its answer, when there
// is one, goes back as a frame. Otherwise it is ordinary silence: the frame
// dropped, the line kept.
func (l *Line) arrive(message []byte) {
	if l.door.Hear != nil {
		if answer, err := l.door.Hear(message); err == nil {
			want := Expect{Warden: answer.Warden, Seq: answer.Seq}
			l.mu.Lock()
			ch, waiting := l.pending[want]
			if waiting {
				delete(l.pending, want)
			}
			l.mu.Unlock()
			if waiting {
				ch <- message
				return
			}
		}
	}
	if l.door.Judge == nil {
		return
	}
	back := l.door.Judge(message)
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

// Caller is the caller a ground with sockets under it holds. It walks the roads
// a peer offered, takes the line wherever one is offered, and falls through to
// the common carriage everywhere else — and nothing at a call site says which,
// because choosing among a peer's hints is the caller's whole job.
//
// Which roads a caller can speak is never configured and never passed. In Go it
// is answered at build time: a program that imports this package has sockets
// under it, and one that does not holds carriage.Caller and speaks the common
// carriage alone. There is no browser under a Go binary, so unlike the JS kit
// there is nothing here to find out at runtime.
//
// The lines it dials are kept, one per road, because a line is persistent by
// definition: a fresh connection per ask would be the common carriage wearing a
// socket, and it would leave a ground that publishes nothing unreachable
// between calls. They belong to the ground that took them up, so HangUp is how
// they are put down.
type Caller struct {
	// Door is what an arriving frame is handed to on a line this caller
	// dialled. A caller without one cannot hold a line, so it walks past every
	// tcp:// hint and posts.
	Door Door

	// Carriage is the common carriage this caller falls through to. Its zero
	// value works.
	Carriage carriage.Caller

	mu    sync.Mutex
	lines map[string]*Line
}

// Send carries the message down the first road this caller can speak that
// actually carried it, and hands back the sealed answer. expect names the ask
// this caller wants an answer to, for the roads that need naming; the common
// carriage needs none, because its answer rides its own response.
//
// A road this caller cannot speak is not a road that failed: nothing was sent,
// so no door spoke and no road broke. It is walked past exactly as a hint that
// was never offered would be, and it is never the fault reported at the end.
func (c *Caller) Send(hints []string, message []byte, expect *Expect) ([]byte, error) {
	var last error
	for _, hint := range hints {
		if strings.HasPrefix(hint, "tcp://") {
			if c.Door.Judge == nil {
				continue
			}
			reply, err := c.overLine(hint, message, expect)
			if err != nil {
				last = err
				continue
			}
			return reply, nil
		}
		reply, err := c.Carriage.Send([]string{hint}, message)
		if err != nil {
			last = err
			continue
		}
		return reply, nil
	}
	if last != nil {
		return nil, last
	}
	// Every hint was a road this caller cannot speak, so no road was tried at
	// all. That is not weather: there is no fault to report the road of.
	return nil, nil
}

func (c *Caller) overLine(hint string, message []byte, expect *Expect) ([]byte, error) {
	c.mu.Lock()
	if c.lines == nil {
		c.lines = map[string]*Line{}
	}
	held, ok := c.lines[hint]
	c.mu.Unlock()
	if !ok || !held.Open() {
		dialled, err := Dial(c.Door, hint)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.lines[hint] = dialled
		c.mu.Unlock()
		held = dialled
	}
	return <-held.Carry(message, expect), nil
}

// HangUp lets go of every line this caller dialled. A line is a held resource
// and the ground that took it up is the one that puts it down.
func (c *Caller) HangUp() {
	c.mu.Lock()
	held := make([]*Line, 0, len(c.lines))
	for _, l := range c.lines {
		held = append(held, l)
	}
	c.lines = nil
	c.mu.Unlock()
	for _, l := range held {
		l.Close()
	}
}
