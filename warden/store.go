package warden

import (
	"maps"
	"slices"
)

// The warden keeps what must survive a restart: both records, the beings'
// names and keys, the replay marks, and the labels. It keeps them in a store
// the host hands in, the way the host hands in the clock and the seeds. The
// store's shape is the warden's; where it lives is the host's.
//
// The beings themselves are pointers and cannot be stored. The host holds the
// same objects again on the same keys after a restart, and the rows find them
// by name.

// InwardRow is one row of the record of who may reach this warden's beings, as
// the store holds it.
type InwardRow struct {
	Voice      [32]byte
	Commitment [32]byte
	Name       [32]byte
	Beings     [][32]byte
	Mark       int64
	Spent      []int64
	Padlock    *[32]byte
	Hints      []string
}

// OutwardRow is one relation this ground holds at another house, as the store
// holds it.
type OutwardRow struct {
	Holder      [32]byte
	Warden      [32]byte
	Commitment  [32]byte
	Padlock     [32]byte
	Voice       [32]byte
	VoiceSecret [32]byte
	HeirSecret  [32]byte
	Hints       []string
	Mark        int64
	Next        int64
	Beings      map[[32]byte][32]byte
}

// LabelRow is one private label beside a row. Labels resolve nothing and
// travel nowhere.
type LabelRow struct {
	Label string
	// Local names a being this warden holds; Far names the house of an
	// outbound row. Exactly one is set.
	Local *[32]byte
	Far   *[32]byte
	// Holder is the being of this ground that spends that relation, because
	// two of them may stand at one house and the label names one of the two.
	Holder *[32]byte
	// Voice is which row, because one being may hold two at one house — a
	// stranger's row from a knock and an accepted one — and warden and holder
	// alone do not tell them apart.
	Voice *[32]byte
	// At is every being reached under that label, with the class of each, so
	// the handles can be rebuilt from the blueprint texts the store also kept.
	At []ReachedRow
}

// ReachedRow is one being reached under a label.
type ReachedRow struct {
	Being  [32]byte
	Digest [32]byte
}

// Snapshot is every fact a restart must not lose, written as plain data.
type Snapshot struct {
	Hints      []string
	Blueprints map[[32]byte]string
	In         []InwardRow
	Out        []OutwardRow
	Labels     []LabelRow
	// Public is what this door offers every voice, in ascending byte order so
	// the snapshot does not differ from itself between runs.
	Public [][32]byte
}

// Store is where a snapshot lives. Its shape is the warden's and its home is
// the host's.
type Store interface {
	Save(Snapshot) error
	Load() (Snapshot, bool, error)
}

// MemoryStore is the default: a store that survives a warden and not a
// process, which is exactly what a restart in one bench needs.
type MemoryStore struct {
	kept Snapshot
	has  bool
}

// Save writes the snapshot.
func (m *MemoryStore) Save(s Snapshot) error {
	m.kept, m.has = s, true
	return nil
}

// Load reads it back, and says whether there was one.
func (m *MemoryStore) Load() (Snapshot, bool, error) { return m.kept, m.has, nil }

// snapshot is the records as the store keeps them.
func (w *Warden) snapshot() Snapshot {
	s := Snapshot{
		Hints:      slices.Clone(w.hints),
		Blueprints: maps.Clone(w.blueprints),
	}
	for _, row := range w.record.in {
		s.In = append(s.In, InwardRow{
			Voice:      row.voice,
			Commitment: row.commitment,
			Name:       row.name,
			Beings:     sortedKeys(row.beings),
			Mark:       row.mark,
			Spent:      window(row.spent, row.mark),
			Padlock:    row.padlock,
			Hints:      slices.Clone(row.hints),
		})
	}
	for _, rel := range w.record.out {
		s.Out = append(s.Out, OutwardRow{
			Holder:      rel.holder,
			Warden:      rel.warden,
			Commitment:  rel.commitment,
			Padlock:     rel.padlock,
			Voice:       rel.voice,
			VoiceSecret: rel.voiceSecret,
			HeirSecret:  rel.heirSecret,
			Hints:       slices.Clone(rel.hints),
			Mark:        rel.mark,
			Next:        rel.next,
			Beings:      maps.Clone(rel.beings),
		})
	}
	for _, name := range slices.Sorted(maps.Keys(w.labels)) {
		kept := w.labels[name]
		one := LabelRow{Label: name}
		if kept.local != nil {
			local := *kept.local
			one.Local = &local
		} else if kept.row != nil {
			far, holder, voice := kept.row.warden, kept.row.holder, kept.row.voice
			one.Far, one.Holder, one.Voice = &far, &holder, &voice
			for _, at := range kept.at {
				one.At = append(one.At, ReachedRow{Being: at.being, Digest: at.digest})
			}
		}
		s.Labels = append(s.Labels, one)
	}
	// The order is derived rather than chosen, because ranging a Go map is
	// randomised and a snapshot that differed from itself between two runs
	// would be a snapshot nobody can compare.
	// Stable, because two rows at one warden compare equal and an unstable
	// sort would order them differently between runs — which is the very
	// thing the comment above says the snapshot must not do.
	slices.SortStableFunc(s.In, func(a, b InwardRow) int { return compareKeys(a.Voice, b.Voice) })
	slices.SortStableFunc(s.Out, func(a, b OutwardRow) int { return compareKeys(a.Warden, b.Warden) })
	for being := range w.public {
		s.Public = append(s.Public, being)
	}
	slices.SortFunc(s.Public, compareKeys)
	return s
}

// persist writes the snapshot, when the host handed a store in. A store that
// falls over is the host's fault and never the caller's: the door answers the
// same either way.
func (w *Warden) persist() {
	if w.store == nil {
		return
	}
	contained(func() { _ = w.store.Save(w.snapshot()) })
}

// restore reads the records back at open, before anything is held. The beings
// are not here: the host holds them again on the same keys, and the rows find
// them by name.
func (w *Warden) restore() error {
	kept, had, err := w.store.Load()
	if err != nil || !had {
		return err
	}
	w.hints = slices.Clone(kept.Hints)
	for digest, text := range kept.Blueprints {
		w.blueprints[digest] = text
	}
	for _, being := range kept.Public {
		w.public[being] = true
	}
	for _, row := range kept.In {
		beings := map[[32]byte]bool{}
		for _, b := range row.Beings {
			beings[b] = true
		}
		spent := map[int64]bool{}
		for _, n := range row.Spent {
			spent[n] = true
		}
		w.record.in[row.Voice] = &inbound{
			voice:      row.Voice,
			commitment: row.Commitment,
			name:       row.Name,
			beings:     beings,
			mark:       row.Mark,
			spent:      spent,
			padlock:    row.Padlock,
			hints:      slices.Clone(row.Hints),
		}
	}
	for _, rel := range kept.Out {
		beings := rel.Beings
		if beings == nil {
			beings = map[[32]byte][32]byte{}
		}
		w.record.out = append(w.record.out, &outbound{
			holder:      rel.Holder,
			warden:      rel.Warden,
			commitment:  rel.Commitment,
			padlock:     rel.Padlock,
			voice:       rel.Voice,
			voiceSecret: rel.VoiceSecret,
			heirSecret:  rel.HeirSecret,
			hints:       slices.Clone(rel.Hints),
			mark:        rel.Mark,
			next:        rel.Next,
			spent:       map[int64]bool{},
			beings:      beings,
			awaiting:    map[await]chan *heard{},
		})
	}
	for _, one := range kept.Labels {
		switch {
		case one.Local != nil:
			local := *one.Local
			w.labels[one.Label] = &label{local: &local}
		case one.Far != nil:
			rel := w.record.rowAt(*one.Far, one.Holder, one.Voice)
			if rel == nil {
				continue
			}
			var at []reached
			for _, kept := range one.At {
				text, known := w.blueprints[kept.Digest]
				if !known {
					continue
				}
				handle, err := w.remote(rel, kept.Being, text)
				if err != nil {
					continue
				}
				at = append(at, reached{being: kept.Being, digest: kept.Digest, handle: handle})
			}
			if len(at) == 0 {
				continue
			}
			w.labels[one.Label] = &label{row: rel, at: at}
		}
	}
	return nil
}

func sortedKeys(m map[[32]byte]bool) [][32]byte {
	out := make([][32]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, compareKeys)
	return out
}
