// Package warden holds the door's judgment: the two records a warden keeps,
// the heir chain, the three describes, and the blueprint every warden holds.
//
// Nothing here touches a carriage. Judge takes the bytes that arrived and
// hands back the bytes to send, or silence. Every failure is the same failure:
// the door answers with silence and never says which step it was, so the
// reasons in this package are for the host and never travel.
package warden

import (
	"errors"
	"fmt"
	"slices"

	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// Blueprint is the one blueprint nobody authors and every warden holds. Its
// digest is the same on every ground in the world, so the warden is not a
// special case in its own protocol.
const Blueprint = `Warden
  describe() estate
  sketch(being being) sketch?
  blueprint(digest b32) text?
  limit() int
  tell(word word)
  moved(being being) word?
  receive(cargo cargo) b32

estate
  classes [class]

class
  digest b32
  beings [held]

held
  being being
  commitment b32

sketch
  being being
  digest b32
  commitment b32

word
  being being?
  successor b32?
  commitment b32?
  name b32?
  padlock b32?
  hints [text]

cargo
  being being
  digest b32
  cells bytes
  standings [standing]
  relations [relation]

standing
  voice b32
  commitment b32
  name b32
  beings [being]
  mark int
  spent [int]
  padlock b32?
  hints [text]

relation
  warden being
  commitment b32
  padlock b32
  voice b32
  secret b32
  heir b32
  heirSecret b32
  seq int
  news int
  hints [text]
`

// Own is the parsed Warden blueprint, and Digest is its identity.
var (
	Own    = mustParse(Blueprint)
	Digest = Own.Digest()
)

// The fields of the Warden blueprint, named once so nothing spells one twice.
const (
	FieldDescribe  = "describe"
	FieldSketch    = "sketch"
	FieldBlueprint = "blueprint"
	FieldLimit     = "limit"
	FieldTell      = "tell"
	FieldMoved     = "moved"
	FieldReceive   = "receive"
)

var (
	estateType = notation.RecordType("estate")
	sketchType = notation.RecordType("sketch")
	wordType   = notation.RecordType("word")
	cargoType  = notation.RecordType("cargo")
)

// Held is one being under a class: its pk, and the heir commitment that lets a
// peer believe its succession when the news comes.
type Held struct {
	Being      [32]byte
	Commitment [32]byte
}

// Class groups the beings of one blueprint. The grouping is the identity: two
// beings of one class carry one digest.
type Class struct {
	Digest [32]byte
	Beings []Held
}

// Estate is every being a voice may reach, given as digests with the pks and
// their commitments under each.
type Estate struct {
	Classes []Class
}

// Sketch describes one being: its pk, its blueprint's digest, and its heir
// commitment. Never its state, because a describe is not a read.
type Sketch struct {
	Being      [32]byte
	Digest     [32]byte
	Commitment [32]byte
}

// Word is news — the word that one key is replaced by another — and the old
// door's pointer, which is why the two carry one shape. The case is read off
// which fields are present, and a field that means nothing in a case is
// absent rather than filled.
type Word struct {
	Being      *[32]byte
	Successor  *[32]byte
	Commitment *[32]byte
	Name       *[32]byte
	Padlock    *[32]byte
	Hints      []string
}

// Standing is one inbound row as it travels with a migrating being. The replay
// record travels whole — the mark and the spent numbers beneath it — or a
// caller's late-arriving in-window numbers would be judged at the new door by a
// window it cannot see.
type Standing struct {
	Voice      [32]byte
	Commitment [32]byte
	// Name is the door name this heir commitment was hashed under. Without it
	// a migrated standing could never verify an older commitment again.
	Name    [32]byte
	Beings  [][32]byte
	Mark    int64
	Spent   []int64
	Padlock *[32]byte
	Hints   []string
}

// Relation is one outbound row as it travels with a migrating being. A being
// that only answers would migrate perfectly without this; a being that acts
// would arrive alive and mute, which is not the same being.
//
// The voice's keys means both of them: Voice and Secret are the key that acts
// now, Heir and HeirSecret the key it committed to at the far door. Carrying
// the voice alone would leave the being able to act once and never able to
// rotate, and would leave the origin holding the one key that can take the
// standing over.
type Relation struct {
	Warden     [32]byte
	Commitment [32]byte
	Padlock    [32]byte
	Voice      [32]byte
	Secret     [32]byte
	Heir       [32]byte
	HeirSecret [32]byte
	Seq        int64
	// News is the mark kept for that far warden's news, which is its own
	// counter and never the one this door sends by.
	News  int64
	Hints []string
}

// Cargo is a migration's state transfer: the being, its class, its cells, and
// both records of standings — the inbound one so its peers keep their standing
// at it, and the outbound one so it keeps its standing at theirs.
type Cargo struct {
	Being     [32]byte
	Digest    [32]byte
	Cells     []byte
	Standings []Standing
	Relations []Relation
}

// Order puts an estate in the order the law derives: classes by their digest
// bytes ascending, beings under each by their pk bytes ascending. The order is
// derived, never chosen, so two wardens describing one estate produce one byte
// sequence.
func (e Estate) Order() Estate {
	classes := slices.Clone(e.Classes)
	for i := range classes {
		classes[i].Beings = slices.Clone(classes[i].Beings)
		slices.SortFunc(classes[i].Beings, func(a, b Held) int {
			return compareKeys(a.Being, b.Being)
		})
	}
	slices.SortFunc(classes, func(a, b Class) int { return compareKeys(a.Digest, b.Digest) })
	return Estate{Classes: classes}
}

func compareKeys(a, b [32]byte) int { return slices.Compare(a[:], b[:]) }

// EncodeEstate writes an estate by the notation's own rules.
func EncodeEstate(e Estate) ([]byte, error) {
	return wire.Encode(Own, estateType, estateValue(e))
}

// DecodeEstate reads one and refuses any byte left after it.
func DecodeEstate(b []byte) (Estate, error) {
	v, err := wire.Decode(Own, estateType, b)
	if err != nil {
		return Estate{}, err
	}
	return readEstate(v)
}

// EncodeSketch writes a sketch.
func EncodeSketch(s Sketch) ([]byte, error) {
	return wire.Encode(Own, sketchType, map[string]any{
		"being": s.Being, "digest": s.Digest, "commitment": s.Commitment,
	})
}

// DecodeSketch reads one.
func DecodeSketch(b []byte) (Sketch, error) {
	v, err := wire.Decode(Own, sketchType, b)
	if err != nil {
		return Sketch{}, err
	}
	f, ok := v.(map[string]any)
	if !ok {
		return Sketch{}, errors.New("warden: that is not a sketch")
	}
	var s Sketch
	if s.Being, err = key(f, "being"); err != nil {
		return Sketch{}, err
	}
	if s.Digest, err = key(f, "digest"); err != nil {
		return Sketch{}, err
	}
	s.Commitment, err = key(f, "commitment")
	return s, err
}

// EncodeWord writes a word.
func EncodeWord(w Word) ([]byte, error) {
	return wire.Encode(Own, wordType, wordValue(w))
}

// DecodeWord reads a word — the arguments of tell, and the answer of moved.
func DecodeWord(b []byte) (Word, error) {
	v, err := wire.Decode(Own, wordType, b)
	if err != nil {
		return Word{}, err
	}
	return readWord(v)
}

// EncodeCargo writes a migration's cargo.
func EncodeCargo(c Cargo) ([]byte, error) {
	return wire.Encode(Own, cargoType, cargoValue(c))
}

// DecodeCargo reads one.
func DecodeCargo(b []byte) (Cargo, error) {
	v, err := wire.Decode(Own, cargoType, b)
	if err != nil {
		return Cargo{}, err
	}
	return readCargo(v)
}

func estateValue(e Estate) map[string]any {
	classes := make([]any, 0, len(e.Classes))
	for _, c := range e.Classes {
		beings := make([]any, 0, len(c.Beings))
		for _, h := range c.Beings {
			beings = append(beings, map[string]any{"being": h.Being, "commitment": h.Commitment})
		}
		classes = append(classes, map[string]any{"digest": c.Digest, "beings": beings})
	}
	return map[string]any{"classes": classes}
}

func wordValue(w Word) map[string]any {
	return map[string]any{
		"being":      optional32(w.Being),
		"successor":  optional32(w.Successor),
		"commitment": optional32(w.Commitment),
		"name":       optional32(w.Name),
		"padlock":    optional32(w.Padlock),
		"hints":      hintList(w.Hints),
	}
}

func cargoValue(c Cargo) map[string]any {
	standings := make([]any, 0, len(c.Standings))
	for _, s := range c.Standings {
		beings := make([]any, 0, len(s.Beings))
		for _, b := range s.Beings {
			beings = append(beings, b)
		}
		spent := make([]any, 0, len(s.Spent))
		for _, n := range s.Spent {
			spent = append(spent, n)
		}
		standings = append(standings, map[string]any{
			"voice":      s.Voice,
			"commitment": s.Commitment,
			"name":       s.Name,
			"beings":     beings,
			"mark":       s.Mark,
			"spent":      spent,
			"padlock":    optional32(s.Padlock),
			"hints":      hintList(s.Hints),
		})
	}
	relations := make([]any, 0, len(c.Relations))
	for _, r := range c.Relations {
		relations = append(relations, map[string]any{
			"warden":     r.Warden,
			"commitment": r.Commitment,
			"padlock":    r.Padlock,
			"voice":      r.Voice,
			"secret":     r.Secret,
			"heir":       r.Heir,
			"heirSecret": r.HeirSecret,
			"seq":        r.Seq,
			"news":       r.News,
			"hints":      hintList(r.Hints),
		})
	}
	cells := c.Cells
	if cells == nil {
		cells = []byte{}
	}
	return map[string]any{
		"being": c.Being, "digest": c.Digest, "cells": cells,
		"standings": standings, "relations": relations,
	}
}

func readEstate(v any) (Estate, error) {
	f, ok := v.(map[string]any)
	if !ok {
		return Estate{}, errors.New("warden: that is not an estate")
	}
	items, ok := f["classes"].([]any)
	if !ok {
		return Estate{}, errors.New("warden: the classes are not a list")
	}
	e := Estate{Classes: make([]Class, 0, len(items))}
	for _, item := range items {
		cf, ok := item.(map[string]any)
		if !ok {
			return Estate{}, errors.New("warden: a class is not a record")
		}
		var c Class
		var err error
		if c.Digest, err = key(cf, "digest"); err != nil {
			return Estate{}, err
		}
		beings, ok := cf["beings"].([]any)
		if !ok {
			return Estate{}, errors.New("warden: the beings are not a list")
		}
		c.Beings = make([]Held, 0, len(beings))
		for _, b := range beings {
			hf, ok := b.(map[string]any)
			if !ok {
				return Estate{}, errors.New("warden: a held being is not a record")
			}
			var h Held
			if h.Being, err = key(hf, "being"); err != nil {
				return Estate{}, err
			}
			if h.Commitment, err = key(hf, "commitment"); err != nil {
				return Estate{}, err
			}
			c.Beings = append(c.Beings, h)
		}
		e.Classes = append(e.Classes, c)
	}
	return e, nil
}

func readWord(v any) (Word, error) {
	f, ok := v.(map[string]any)
	if !ok {
		return Word{}, errors.New("warden: that is not a word")
	}
	var w Word
	var err error
	for name, into := range map[string]**[32]byte{
		"being": &w.Being, "successor": &w.Successor, "commitment": &w.Commitment,
		"name": &w.Name, "padlock": &w.Padlock,
	} {
		if *into, err = maybeKey(f, name); err != nil {
			return Word{}, err
		}
	}
	w.Hints, err = readHints(f["hints"])
	return w, err
}

func readCargo(v any) (Cargo, error) {
	f, ok := v.(map[string]any)
	if !ok {
		return Cargo{}, errors.New("warden: that is not a cargo")
	}
	var c Cargo
	var err error
	if c.Being, err = key(f, "being"); err != nil {
		return Cargo{}, err
	}
	if c.Digest, err = key(f, "digest"); err != nil {
		return Cargo{}, err
	}
	if c.Cells, ok = f["cells"].([]byte); !ok {
		return Cargo{}, errors.New("warden: the cells are not bytes")
	}
	items, ok := f["standings"].([]any)
	if !ok {
		return Cargo{}, errors.New("warden: the standings are not a list")
	}
	c.Standings = make([]Standing, 0, len(items))
	for _, item := range items {
		sf, ok := item.(map[string]any)
		if !ok {
			return Cargo{}, errors.New("warden: a standing is not a record")
		}
		var s Standing
		if s.Voice, err = key(sf, "voice"); err != nil {
			return Cargo{}, err
		}
		if s.Commitment, err = key(sf, "commitment"); err != nil {
			return Cargo{}, err
		}
		if s.Name, err = key(sf, "name"); err != nil {
			return Cargo{}, err
		}
		beings, ok := sf["beings"].([]any)
		if !ok {
			return Cargo{}, errors.New("warden: the beings are not a list")
		}
		for _, b := range beings {
			k, ok := b.([32]byte)
			if !ok {
				return Cargo{}, errors.New("warden: a being is not a key")
			}
			s.Beings = append(s.Beings, k)
		}
		if s.Mark, ok = sf["mark"].(int64); !ok {
			return Cargo{}, errors.New("warden: the mark is not a number")
		}
		numbers, ok := sf["spent"].([]any)
		if !ok {
			return Cargo{}, errors.New("warden: the spent numbers are not a list")
		}
		s.Spent = make([]int64, 0, len(numbers))
		for _, n := range numbers {
			seq, ok := n.(int64)
			if !ok {
				return Cargo{}, errors.New("warden: a spent number is not a number")
			}
			s.Spent = append(s.Spent, seq)
		}
		if s.Padlock, err = maybeKey(sf, "padlock"); err != nil {
			return Cargo{}, err
		}
		if s.Hints, err = readHints(sf["hints"]); err != nil {
			return Cargo{}, err
		}
		c.Standings = append(c.Standings, s)
	}
	rows, ok := f["relations"].([]any)
	if !ok {
		return Cargo{}, errors.New("warden: the relations are not a list")
	}
	c.Relations = make([]Relation, 0, len(rows))
	for _, item := range rows {
		rf, ok := item.(map[string]any)
		if !ok {
			return Cargo{}, errors.New("warden: a relation is not a record")
		}
		var r Relation
		for name, into := range map[string]*[32]byte{
			"warden": &r.Warden, "commitment": &r.Commitment, "padlock": &r.Padlock,
			"voice": &r.Voice, "secret": &r.Secret,
			"heir": &r.Heir, "heirSecret": &r.HeirSecret,
		} {
			if *into, err = key(rf, name); err != nil {
				return Cargo{}, err
			}
		}
		if r.Seq, ok = rf["seq"].(int64); !ok {
			return Cargo{}, errors.New("warden: the seq is not a number")
		}
		if r.News, ok = rf["news"].(int64); !ok {
			return Cargo{}, errors.New("warden: the news mark is not a number")
		}
		if r.Hints, err = readHints(rf["hints"]); err != nil {
			return Cargo{}, err
		}
		c.Relations = append(c.Relations, r)
	}
	return c, nil
}

func readHints(v any) ([]string, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New("warden: the hints are not a list")
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("warden: a hint is not text")
		}
		out = append(out, s)
	}
	return out, nil
}

func hintList(hints []string) []any {
	out := make([]any, 0, len(hints))
	for _, h := range hints {
		out = append(out, h)
	}
	return out
}

func key(f map[string]any, name string) ([32]byte, error) {
	k, ok := f[name].([32]byte)
	if !ok {
		return [32]byte{}, fmt.Errorf("warden: %s is not a key", name)
	}
	return k, nil
}

func maybeKey(f map[string]any, name string) (*[32]byte, error) {
	if f[name] == nil {
		return nil, nil
	}
	k, err := key(f, name)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func optional32(k *[32]byte) any {
	if k == nil {
		return nil
	}
	return *k
}

func mustParse(text string) *notation.Blueprint {
	bp, err := notation.Parse(text)
	if err != nil {
		panic(err)
	}
	return bp
}
