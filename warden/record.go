package warden

import (
	"errors"
	"maps"
	"slices"

	"quo.systems/kit/arithmetic"
)

// DefaultWindow is how far below its mark this warden still honours a number.
// How wide the window is, is the warden's own — wider is more forgiving of a
// rough road, and no peer can tell the difference except by being refused.
const DefaultWindow = 64

// inbound is one row of the record that says which voices may reach which of
// this warden's beings. It is binary per being, because that is all a warden
// is able to know.
type inbound struct {
	voice      [32]byte
	commitment [32]byte // the heir's, hashed under the name below
	// name is the name this door wore when the commitment was minted. Every
	// commitment was hashed with a door's name inside it, so a door that
	// succeeded its name keeps verifying an older standing's heir at the name
	// it was minted at, and mints new commitments under the new one. It is
	// held in memory and rides nowhere.
	name    [32]byte
	beings  map[[32]byte]bool
	mark    int64
	spent   map[int64]bool // the numbers below the mark already honoured
	padlock *[32]byte      // how to answer this voice, refreshed by every call
	hints   []string
	label   string // a private label; it resolves nothing and travels nowhere
}

// outbound is one row of the record of the relations this warden's beings may
// spend: the invitation kept whole, and the marks and commitments the peer
// needs to believe news from that house.
type outbound struct {
	// holder is the being of this ground that may spend the relation. The
	// record is which of its beings may spend which relation, so a row that
	// named no being could not travel when that being moves.
	holder      [32]byte
	warden      [32]byte // the far warden's pk, the name
	commitment  [32]byte // the hash of that warden's heir
	padlock     [32]byte // what to seal to for this relation
	voice       [32]byte // the current voice this ground holds there
	voiceSecret [32]byte
	hints       []string
	mark        int64 // one mark per far warden, for the news it sends
	spent       map[int64]bool
	// next is this ground's own count at that door. Per voice the number only
	// rises, so the counter belongs beside the voice that spends it.
	next int64
	// heirSecret is the key this ground committed to at its last rotation and
	// will spend at its next. Nothing in Quo carries it, so the row keeps it.
	heirSecret [32]byte
	// beings holds the heir commitment of each being this ground stands at
	// under that warden. The invitation carries only the warden's own
	// commitment; a being's arrives in the describe, and a peer that did not
	// keep it could not believe that being's succession.
	beings map[[32]byte][32]byte
	label  string
	// awaiting is the asks this ground has put on a road down this relation
	// and has not yet heard an answer to. Article XII's fourth check on an
	// answer is that one is awaiting under that padlock, that warden and that
	// seq, so the caller keeps the record that check reads.
	awaiting map[await]bool
}

// await is one ask still out: the number it spent and the padlock it told the
// far door to seal the answer to. The warden is the row it hangs on. Two asks
// carrying the same three are two asks whose answers cannot be told apart,
// which is what a caller's own kit refuses to send — and a rotation, which
// starts the far door's mark fresh, is how a number comes round again.
type await struct {
	seq     int64
	padlock [32]byte
}

// record is the pair of records a warden keeps. They are not the same shape.
type record struct {
	in     map[[32]byte]*inbound
	out    map[[32]byte]*outbound // keyed by the far warden's pk
	window int64
}

func newRecord(window int64) *record {
	return &record{in: map[[32]byte]*inbound{}, out: map[[32]byte]*outbound{}, window: window}
}

// heir finds the standing whose committed heir this voice is. The commitment
// binds the key and the place together, so a heir committed at another door
// hashes to nothing here.
//
// Each row is hashed against the name its own commitment was minted under,
// never the name the door wears now: after a name succession an older standing
// must still be able to rotate.
func (r *record) heir(voice [32]byte) *inbound {
	for _, row := range r.in {
		if arithmetic.Commit(row.name, voice) == row.commitment {
			return row
		}
	}
	return nil
}

// rotate hands a standing over: the pk becomes the current holder, the carried
// commitment becomes the new heir, the old key dies, and the mark starts
// fresh, because the new holder never saw the numbers the old one counted.
func (r *record) rotate(row *inbound, voice, commitment, name [32]byte) {
	delete(r.in, row.voice)
	row.voice = voice
	row.commitment = commitment
	// New commitments are minted under the name the door has now.
	row.name = name
	row.mark = 0
	row.spent = map[int64]bool{}
	r.in[voice] = row
}

// spend takes a number against a mark and a window. A message above the mark
// is honoured and moves it; a message inside the window is honoured once and
// never again; a message below the window is silence, because a door that
// remembered every number ever seen would be a door with unbounded memory.
//
// A number once spent stays spent whatever happens after: nothing refunds it,
// so a door is never replayable through its own refusals.
func spend(mark *int64, spent map[int64]bool, window, seq int64) error {
	switch {
	case seq < 1:
		return errors.New("warden: the first legal number is one")
	case seq <= *mark-window:
		return errors.New("warden: a number below the window")
	case seq == *mark:
		// The mark is the highest number honoured, so it is spent by
		// definition, whether or not the window still remembers saying so.
		return errors.New("warden: a number already spent")
	case spent[seq]:
		return errors.New("warden: a number already spent")
	}
	spent[seq] = true
	if seq > *mark {
		// The number the mark held is honoured — that is what a mark is — and
		// must stay honoured as the mark moves off it. Ordinarily it is in the
		// set already, because it was spent through here; a mark that arrived
		// in a cargo never was, and a mark that simply moved would leave that
		// number free to be honoured a second time.
		if was := *mark; was >= 1 {
			spent[was] = true
		}
		*mark = seq
		forget(spent, *mark, window)
	}
	return nil
}

// window is the replay record as it travels: the numbers below the mark already
// honoured, ascending, so two kits packing one row agree on the bytes. The mark
// itself is spent by definition and is carried as the mark.
func window(spent map[int64]bool, mark int64) []int64 {
	out := []int64{}
	for n := range spent {
		if n < mark {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// forget drops what has fallen out of the window, so the memory is bounded.
func forget(spent map[int64]bool, mark, window int64) {
	for _, n := range slices.Collect(maps.Keys(spent)) {
		if n <= mark-window {
			delete(spent, n)
		}
	}
}
