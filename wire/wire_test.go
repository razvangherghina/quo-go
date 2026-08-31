package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"quo.systems/kit/internal/corpus"
	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

func TestCorpus(t *testing.T) {
	file, err := corpus.Load("wire")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the corpus is empty")
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			bp, err := notation.Parse(v.Blueprint)
			if err != nil {
				t.Fatalf("the vector's own blueprint was refused: %v", err)
			}
			if len(bp.Fields) != 1 || bp.Fields[0].Answer == nil {
				t.Fatalf("a vector names a class with exactly one answering field")
			}
			under := *bp.Fields[0].Answer

			want, err := hex.DecodeString(v.Bytes)
			if err != nil {
				t.Fatal(err)
			}

			if v.Refuses {
				if _, err := wire.Decode(bp, under, want); err == nil {
					t.Fatalf("accepted what the corpus refuses: %s", v.Bytes)
				}
				return
			}

			value, err := fromJSON(bp, under, v.Value)
			if err != nil {
				t.Fatal(err)
			}
			got, err := wire.Encode(bp, under, value)
			if err != nil {
				t.Fatalf("refused to encode: %v", err)
			}
			if hex.EncodeToString(got) != v.Bytes {
				t.Fatalf("bytes\n got %s\nwant %s", hex.EncodeToString(got), v.Bytes)
			}

			// The other direction: the corpus's bytes read, then written back.
			back, err := wire.Decode(bp, under, want)
			if err != nil {
				t.Fatalf("refused to decode: %v", err)
			}
			round, err := wire.Encode(bp, under, back)
			if err != nil {
				t.Fatalf("refused to re-encode: %v", err)
			}
			if hex.EncodeToString(round) != v.Bytes {
				t.Fatalf("round trip\n got %s\nwant %s", hex.EncodeToString(round), v.Bytes)
			}
		})
	}
}

// TestOptionalOptionalAbsentInner covers the one shape the corpus's JSON
// cannot write: an optional that is present holding an optional that is
// absent.
func TestOptionalOptionalAbsentInner(t *testing.T) {
	bp, err := notation.Parse("Probe\n  probe() int??\n")
	if err != nil {
		t.Fatal(err)
	}
	under := *bp.Fields[0].Answer

	got, err := wire.Encode(bp, under, wire.Opt{Value: nil})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "0100" {
		t.Fatalf("got %s want 0100", hex.EncodeToString(got))
	}
	back, err := wire.Decode(bp, under, got)
	if err != nil {
		t.Fatal(err)
	}
	if back != (wire.Opt{Value: nil}) {
		t.Fatalf("got %#v", back)
	}
}

// fromJSON reads a vector's value by the one rule per type the corpus README
// states.
func fromJSON(bp *notation.Blueprint, t notation.Type, raw json.RawMessage) (any, error) {
	switch t.Kind {
	case notation.KindBool:
		var v bool
		err := json.Unmarshal(raw, &v)
		return v, err
	case notation.KindInt:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		return strconv.ParseInt(s, 10, 64)
	case notation.KindText:
		var v string
		err := json.Unmarshal(raw, &v)
		return v, err
	case notation.KindBytes:
		return hexBytes(raw)
	case notation.KindB32, notation.KindBeing:
		return hex32(raw)
	case notation.KindInvitation:
		var o struct {
			Warden     json.RawMessage `json:"warden"`
			Commitment json.RawMessage `json:"commitment"`
			Padlock    json.RawMessage `json:"padlock"`
			Heir       json.RawMessage `json:"heir"`
			HeirSecret json.RawMessage `json:"heirSecret"`
			Hints      []string        `json:"hints"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		inv := wire.Invitation{Hints: o.Hints}
		into := []*[32]byte{&inv.Warden, &inv.Commitment, &inv.Padlock, &inv.Heir, &inv.HeirSecret}
		for i, src := range []json.RawMessage{o.Warden, o.Commitment, o.Padlock, o.Heir, o.HeirSecret} {
			k, err := hex32(src)
			if err != nil {
				return nil, err
			}
			*into[i] = k
		}
		return inv, nil
	case notation.KindCard:
		// The corpus does not carry a card yet. This reads one by the same rule
		// the README states for an invitation, minus the keypair, so a re-emitted
		// corpus meets this kit's reading without it being bent to fit.
		var o struct {
			Warden     json.RawMessage `json:"warden"`
			Commitment json.RawMessage `json:"commitment"`
			Padlock    json.RawMessage `json:"padlock"`
			Hints      []string        `json:"hints"`
		}
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		card := wire.Card{Hints: o.Hints}
		into := []*[32]byte{&card.Warden, &card.Commitment, &card.Padlock}
		for i, src := range []json.RawMessage{o.Warden, o.Commitment, o.Padlock} {
			k, err := hex32(src)
			if err != nil {
				return nil, err
			}
			*into[i] = k
		}
		return card, nil
	case notation.KindList:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, err
		}
		out := make([]any, 0, len(items))
		for _, item := range items {
			v, err := fromJSON(bp, *t.Elem, item)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case notation.KindOptional:
		if len(raw) == 0 || string(raw) == "null" {
			return nil, nil
		}
		v, err := fromJSON(bp, *t.Elem, raw)
		if err != nil {
			return nil, err
		}
		if t.Elem.Kind == notation.KindOptional {
			return wire.Opt{Value: v}, nil
		}
		return v, nil
	case notation.KindRecord:
		r, ok := bp.Record(t.Name)
		if !ok {
			return nil, fmt.Errorf("no block declares %q", t.Name)
		}
		var o map[string]json.RawMessage
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		fields := make(map[string]any, len(r.Members))
		for _, m := range r.Members {
			v, err := fromJSON(bp, m.Type, o[m.Name])
			if err != nil {
				return nil, err
			}
			fields[m.Name] = v
		}
		return fields, nil
	}
	return nil, fmt.Errorf("unknown kind %d", t.Kind)
}

func hexBytes(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

func hex32(raw json.RawMessage) ([32]byte, error) {
	var k [32]byte
	b, err := hexBytes(raw)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("a b32 that is %d bytes", len(b))
	}
	copy(k[:], b)
	return k, nil
}
