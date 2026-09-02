// Package wire encodes and decodes the closed types.
//
// Each type has exactly one way of being written, and a decoder refuses
// everything the notation does not describe — a marker byte that is neither
// present nor absent, a negative length, bytes left over after a well-formed
// value. Every refusal is the same refusal; the reasons here are for the
// host, and never travel.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"quo.systems/kit/notation"
)

// Invitation is the five things a holder holds, as one typed value.
type Invitation struct {
	Warden     [32]byte
	Commitment [32]byte
	Padlock    [32]byte
	Heir       [32]byte
	HeirSecret [32]byte
	Hints      []string
}

// Card is the four things a stranger holds, as one typed value. It is the
// invitation with the keypair struck out — nothing was granted — and the
// fields it keeps ride exactly as they ride there.
type Card struct {
	Warden     [32]byte
	Commitment [32]byte
	Padlock    [32]byte
	Hints      []string
}

// Opt marks an optional's value as present. A nil value is absent, so Opt is
// needed only to tell an absent inner optional from an absent outer one.
type Opt struct{ Value any }

// Encode writes v as the type t declares, resolving record names in bp.
//
// A value is held as: bool, int64, string, []byte, [32]byte for b32 and
// being, Invitation, Card, []any for a list, map[string]any for a record, and nil
// for an absent optional.
func Encode(bp *notation.Blueprint, t notation.Type, v any) ([]byte, error) {
	var out []byte
	if err := encode(bp, t, v, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Decode reads one value of type t and refuses any byte left after it.
func Decode(bp *notation.Blueprint, t notation.Type, b []byte) (any, error) {
	d := &decoder{b: b}
	v, err := d.value(bp, t)
	if err != nil {
		return nil, err
	}
	if d.pos != len(d.b) {
		return nil, errors.New("wire: bytes left over after the value")
	}
	return v, nil
}

// DecodeAll reads one value of each type in turn out of one blob, and refuses
// any byte left after the last. A field's arguments ride as its declared
// argument types in declared order, concatenated, so this is how the receiving
// side reads them — the arguments do not carry a count of their own, and the
// blueprint is what says how many there are.
func DecodeAll(bp *notation.Blueprint, ts []notation.Type, b []byte) ([]any, error) {
	d := &decoder{b: b}
	out := make([]any, 0, len(ts))
	for _, t := range ts {
		v, err := d.value(bp, t)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if d.pos != len(d.b) {
		return nil, errors.New("wire: bytes left over after the values")
	}
	return out, nil
}

func encode(bp *notation.Blueprint, t notation.Type, v any, out *[]byte) error {
	switch t.Kind {
	case notation.KindBool:
		b, ok := v.(bool)
		if !ok {
			return typeErr(t, v)
		}
		if b {
			*out = append(*out, 1)
		} else {
			*out = append(*out, 0)
		}
	case notation.KindInt:
		n, ok := v.(int64)
		if !ok {
			return typeErr(t, v)
		}
		appendInt(out, n)
	case notation.KindText:
		s, ok := v.(string)
		if !ok {
			return typeErr(t, v)
		}
		if !utf8.ValidString(s) {
			return errors.New("wire: text that is not UTF-8")
		}
		appendLen(out, len(s))
		*out = append(*out, s...)
	case notation.KindBytes:
		b, ok := v.([]byte)
		if !ok {
			return typeErr(t, v)
		}
		appendLen(out, len(b))
		*out = append(*out, b...)
	case notation.KindB32, notation.KindBeing:
		b, ok := v.([32]byte)
		if !ok {
			return typeErr(t, v)
		}
		*out = append(*out, b[:]...)
	case notation.KindInvitation:
		inv, ok := v.(Invitation)
		if !ok {
			return typeErr(t, v)
		}
		for _, k := range [][32]byte{inv.Warden, inv.Commitment, inv.Padlock, inv.Heir, inv.HeirSecret} {
			*out = append(*out, k[:]...)
		}
		return appendHints(out, inv.Hints)
	case notation.KindCard:
		card, ok := v.(Card)
		if !ok {
			return typeErr(t, v)
		}
		for _, k := range [][32]byte{card.Warden, card.Commitment, card.Padlock} {
			*out = append(*out, k[:]...)
		}
		return appendHints(out, card.Hints)
	case notation.KindList:
		items, ok := v.([]any)
		if !ok {
			return typeErr(t, v)
		}
		appendLen(out, len(items))
		for _, item := range items {
			if err := encode(bp, *t.Elem, item, out); err != nil {
				return err
			}
		}
	case notation.KindOptional:
		if v == nil {
			*out = append(*out, 0)
			return nil
		}
		*out = append(*out, 1)
		if o, ok := v.(Opt); ok {
			v = o.Value
		}
		return encode(bp, *t.Elem, v, out)
	case notation.KindRecord:
		r, ok := bp.Record(t.Name)
		if !ok {
			return fmt.Errorf("wire: no block declares %q", t.Name)
		}
		fields, ok := v.(map[string]any)
		if !ok {
			return typeErr(t, v)
		}
		for _, m := range r.Members {
			f, held := fields[m.Name]
			if !held && m.Type.Kind != notation.KindOptional {
				return fmt.Errorf("wire: %s.%s is missing", r.Name, m.Name)
			}
			if err := encode(bp, m.Type, f, out); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("wire: unknown kind %d", t.Kind)
	}
	return nil
}

type decoder struct {
	b   []byte
	pos int
}

func (d *decoder) take(n int) ([]byte, error) {
	if n < 0 || n > len(d.b)-d.pos {
		return nil, errors.New("wire: short of the value")
	}
	b := d.b[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// count reads a length or a count. Both are written the way an int is and are
// non-negative by rule, and neither may run past what the receiver can
// address.
func (d *decoder) count() (int, error) {
	b, err := d.take(8)
	if err != nil {
		return 0, err
	}
	n := int64(binary.BigEndian.Uint64(b))
	if n < 0 {
		return 0, errors.New("wire: a negative length")
	}
	if n > math.MaxInt || int(n) > len(d.b)-d.pos {
		return 0, errors.New("wire: a length beyond the bytes that remain")
	}
	return int(n), nil
}

func (d *decoder) b32() ([32]byte, error) {
	var k [32]byte
	b, err := d.take(32)
	if err != nil {
		return k, err
	}
	copy(k[:], b)
	return k, nil
}

func (d *decoder) hints() ([]string, error) {
	n, err := d.count()
	if err != nil {
		return nil, err
	}
	hints := make([]string, 0, n)
	for range n {
		v, err := d.value(nil, notation.Type{Kind: notation.KindText})
		if err != nil {
			return nil, err
		}
		hints = append(hints, v.(string))
	}
	return hints, nil
}

func (d *decoder) value(bp *notation.Blueprint, t notation.Type) (any, error) {
	switch t.Kind {
	case notation.KindBool:
		b, err := d.take(1)
		if err != nil {
			return nil, err
		}
		switch b[0] {
		case 0:
			return false, nil
		case 1:
			return true, nil
		}
		return nil, errors.New("wire: a bool that is neither zero nor one")
	case notation.KindInt:
		b, err := d.take(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case notation.KindText:
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, errors.New("wire: text that is not UTF-8")
		}
		return string(b), nil
	case notation.KindBytes:
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		b, err := d.take(n)
		if err != nil {
			return nil, err
		}
		// Never a nil slice: a `bytes?` that is present and empty and one that
		// is absent are two different messages, and a language that conflates
		// nil with empty sends the wrong one.
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	case notation.KindB32, notation.KindBeing:
		return d.b32()
	case notation.KindInvitation:
		var inv Invitation
		for _, k := range []*[32]byte{&inv.Warden, &inv.Commitment, &inv.Padlock, &inv.Heir, &inv.HeirSecret} {
			v, err := d.b32()
			if err != nil {
				return nil, err
			}
			*k = v
		}
		hints, err := d.hints()
		if err != nil {
			return nil, err
		}
		inv.Hints = hints
		return inv, nil
	case notation.KindCard:
		var card Card
		for _, k := range []*[32]byte{&card.Warden, &card.Commitment, &card.Padlock} {
			v, err := d.b32()
			if err != nil {
				return nil, err
			}
			*k = v
		}
		hints, err := d.hints()
		if err != nil {
			return nil, err
		}
		card.Hints = hints
		return card, nil
	case notation.KindList:
		n, err := d.count()
		if err != nil {
			return nil, err
		}
		items := make([]any, 0, n)
		for range n {
			item, err := d.value(bp, *t.Elem)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case notation.KindOptional:
		b, err := d.take(1)
		if err != nil {
			return nil, err
		}
		switch b[0] {
		case 0:
			return nil, nil
		case 1:
			v, err := d.value(bp, *t.Elem)
			if err != nil {
				return nil, err
			}
			if t.Elem.Kind == notation.KindOptional {
				return Opt{Value: v}, nil
			}
			return v, nil
		}
		return nil, errors.New("wire: a marker that is neither present nor absent")
	case notation.KindRecord:
		r, ok := bp.Record(t.Name)
		if !ok {
			return nil, fmt.Errorf("wire: no block declares %q", t.Name)
		}
		fields := make(map[string]any, len(r.Members))
		for _, m := range r.Members {
			v, err := d.value(bp, m.Type)
			if err != nil {
				return nil, err
			}
			fields[m.Name] = v
		}
		return fields, nil
	}
	return nil, fmt.Errorf("wire: unknown kind %d", t.Kind)
}

func appendInt(out *[]byte, n int64) {
	*out = binary.BigEndian.AppendUint64(*out, uint64(n))
}

func appendLen(out *[]byte, n int) { appendInt(out, int64(n)) }

// appendHints writes the hints as [text], which is how they ride in both the
// invitation and the card.
func appendHints(out *[]byte, hints []string) error {
	appendLen(out, len(hints))
	for _, h := range hints {
		if !utf8.ValidString(h) {
			return errors.New("wire: text that is not UTF-8")
		}
		appendLen(out, len(h))
		*out = append(*out, h...)
	}
	return nil
}

func typeErr(t notation.Type, v any) error {
	return fmt.Errorf("wire: %T is not a %s", v, t)
}
