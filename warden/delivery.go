package warden

import (
	"fmt"
	"slices"
)

// Row is what delivery is given per message: the way back and nothing else. A
// hint is an opaque string that says where bytes go, and the warden never
// parses one — it holds addresses and knows nothing about roads.
type Row struct {
	Padlock [32]byte
	Hints   []string
}

// Weather is a road that was tried and never carried the bytes: a connection
// refused, a name that does not resolve, a line that dropped. The far door
// never heard, so nothing moved there and the number was spent on this side
// alone — which is why it is never the far door's silence and is never made to
// look like it. Tried is the roads actually tried and broken, never one walked
// past because nobody here could speak it.
type Weather struct {
	Tried []string
	Cause error
}

func (w *Weather) Error() string {
	return fmt.Sprintf("weather: no road carried the bytes (tried %v)", w.Tried)
}

func (w *Weather) Unwrap() error { return w.Cause }

// NoRoad is every hint offered being one this ground cannot speak, with no
// line to fall back to. Nothing was sent, so no door heard and no road broke:
// Article III says it is neither silence nor weather, and it is reported apart.
type NoRoad struct {
	Hints []string
}

func (n *NoRoad) Error() string {
	return fmt.Sprintf("no road: none of the hints offered is one this ground can speak (%v)", n.Hints)
}

// Delivery is the one thing beneath the warden that reads a hint. It has three
// rules and no more, and they belong to the host: a row with hints goes to the
// first road this ground can speak; a row without goes down the line that
// padlock's last ask arrived on, if still held; neither carried, and which of
// the two it was comes back as the error.
type Delivery interface {
	// Send hands one envelope out. Bytes back are a road that answered in its
	// own response. No bytes and later means a road that answers through the
	// warden's door as a message of its own, so the caller waits. An error is
	// no road having carried: *Weather for a road that broke, *NoRoad for
	// hints nobody here can speak.
	Send(row Row, message []byte) (back []byte, later bool, err error)

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
// one. A hint nothing is attached under is a door that is down, which at
// distance zero is the whole of weather; a row without hints has no road here
// to ride at all.
func (m *Memory) Send(row Row, message []byte) ([]byte, bool, error) {
	for _, fn := range m.watched {
		fn(Row{Padlock: row.Padlock, Hints: slices.Clone(row.Hints)})
	}
	for _, hint := range row.Hints {
		far, ok := m.doors[hint]
		if !ok {
			continue
		}
		return far.Arrive(message, nil), false, nil
	}
	if len(row.Hints) == 0 {
		return nil, false, &NoRoad{}
	}
	return nil, false, &Weather{Tried: slices.Clone(row.Hints)}
}

// Arrived is nothing here: at distance zero there is no line to remember, so a
// row without hints has nothing to ride.
func (m *Memory) Arrived([32]byte, any) {}
