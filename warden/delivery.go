package warden

import "slices"

// Row is what delivery is given per message: the way back and nothing else. A
// hint is an opaque string that says where bytes go, and the warden never
// parses one — it holds addresses and knows nothing about roads.
type Row struct {
	Padlock [32]byte
	Hints   []string
}

// Delivery is the one thing beneath the warden that reads a hint. It has three
// rules and no more, and they belong to the host: a row with hints goes to the
// first road this ground can speak; a row without goes down the line that
// padlock's last ask arrived on, if still held; neither is weather, and the
// number was spent.
type Delivery interface {
	// Send hands one envelope out. Bytes back are a road that answered in its
	// own response. No bytes and later means a road that answers through the
	// warden's door as a message of its own, so the caller waits. No bytes and
	// not later is weather.
	Send(row Row, message []byte) (back []byte, later bool)

	// Arrived is the warden's one call downward: having judged a frame, it
	// hands delivery the caller's padlock beside the opaque token the road
	// gave it, and nothing more. Nothing comes back.
	Arrived(padlock [32]byte, via any)
}

// Memory is delivery at distance zero: bytes handed straight to another
// warden's one entry point, in this process, with no step waived. It is the
// default a host that stands no road gets, and what a bench runs on.
type Memory struct {
	doors   map[string]*Warden
	watched []func(Row)
}

// NewMemory stands one. Two wardens attached to it find each other the way two
// wardens in one device would.
func NewMemory() *Memory { return &Memory{doors: map[string]*Warden{}} }

// Attach puts a warden behind a hint.
func (m *Memory) Attach(hint string, w *Warden) { m.doors[hint] = w }

// Detach takes one away. A road that has stopped carrying is not a road.
func (m *Memory) Detach(hint string) { delete(m.doors, hint) }

// Watch is told every row delivery is handed, so a bench can assert that what
// crosses this line is the way back and nothing else.
func (m *Memory) Watch(fn func(Row)) { m.watched = append(m.watched, fn) }

// Send walks the hints and hands the bytes to the first door attached under
// one. A row with no hint this delivery can speak is weather.
func (m *Memory) Send(row Row, message []byte) ([]byte, bool) {
	for _, fn := range m.watched {
		fn(Row{Padlock: row.Padlock, Hints: slices.Clone(row.Hints)})
	}
	for _, hint := range row.Hints {
		far, ok := m.doors[hint]
		if !ok {
			continue
		}
		return far.Arrive(message, nil), false
	}
	return nil, false
}

// Arrived is nothing here: at distance zero there is no line to remember, so a
// row without hints has nothing to ride and is weather.
func (m *Memory) Arrived([32]byte, any) {}
