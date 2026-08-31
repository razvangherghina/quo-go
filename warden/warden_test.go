package warden_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"quo.systems/kit/internal/corpus"
	"quo.systems/kit/notation"
	"quo.systems/kit/warden"
)

func TestCorpus(t *testing.T) {
	file, err := corpus.Load("warden")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the corpus is empty")
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			switch {
			case v.Has("unordered"):
				checkOrder(t, v)
			case v.Has("digest"):
				checkBlueprint(t, v)
			default:
				t.Fatal("no assertion fits this vector")
			}
		})
	}
}

// theCorpusIsBehind names the vectors the corpus was emitted for before the
// law ruled otherwise. A vector that disagrees with the law is a finding
// against whatever emitted it, never a reason to bend this kit — so the case
// is stated here with its reason, and the entry goes the day the corpus is
// emitted again.
var theCorpusIsBehind = map[string]string{}

// checkBlueprint asserts the one blueprint nobody authors: the text this kit
// read out of the law is the text the corpus holds, and so is its digest.
func checkBlueprint(t *testing.T, v corpus.Vector) {
	if why, behind := theCorpusIsBehind[v.Name]; behind {
		t.Skip(why)
	}
	if v.Blueprint != warden.Blueprint {
		t.Fatalf("the blueprint\n got %q\nwant %q", warden.Blueprint, v.Blueprint)
	}
	if got := hex.EncodeToString([]byte(warden.Own.Text())); got != v.Canonical {
		t.Errorf("canonical text\n got %s\nwant %s", got, v.Canonical)
	}
	if got := hex.EncodeToString(warden.Digest[:]); got != v.Digest {
		t.Errorf("digest\n got %s\nwant %s", got, v.Digest)
	}
}

// checkOrder asserts the derived order and the bytes it produces, both ways.
// Two wardens describing one estate produce one byte sequence.
func checkOrder(t *testing.T, v corpus.Vector) {
	sameShape(t, v.Blueprint)

	unordered := readEstate(t, rawOf(t, v, "unordered"))
	want := readEstate(t, v.Value)

	got := unordered.Order()
	if !sameEstate(got, want) {
		t.Fatalf("ordered to %#v\nwant %#v", got, want)
	}

	bytes, err := warden.EncodeEstate(got)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(bytes) != v.Bytes {
		t.Fatalf("bytes\n got %s\nwant %s", hex.EncodeToString(bytes), v.Bytes)
	}

	raw, err := hex.DecodeString(v.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	back, err := warden.DecodeEstate(raw)
	if err != nil {
		t.Fatalf("refused to decode: %v", err)
	}
	if !sameEstate(back, want) {
		t.Fatalf("decoded to %#v", back)
	}
	round, err := warden.EncodeEstate(back)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(round) != v.Bytes {
		t.Fatalf("round trip\n got %s\nwant %s", hex.EncodeToString(round), v.Bytes)
	}
}

// sameShape compares the record blocks the corpus wrote with the ones this kit
// holds. The vector's own class is its own; only the shared records matter.
func sameShape(t *testing.T, blueprint string) {
	t.Helper()
	theirs, err := notation.Parse(blueprint)
	if err != nil {
		t.Fatalf("the vector's own blueprint was refused: %v", err)
	}
	for _, block := range theirs.Records {
		mine, ok := warden.Own.Record(block.Name)
		if !ok {
			t.Fatalf("the corpus declares %q and this kit does not", block.Name)
		}
		if len(mine.Members) != len(block.Members) {
			t.Fatalf("%s has %d members here and %d in the corpus",
				block.Name, len(mine.Members), len(block.Members))
		}
		for i, m := range block.Members {
			if mine.Members[i].Name != m.Name || mine.Members[i].Type.String() != m.Type.String() {
				t.Fatalf("%s field %d is %s %s here and %s %s in the corpus",
					block.Name, i, mine.Members[i].Name, mine.Members[i].Type, m.Name, m.Type)
			}
		}
	}
}

// TestOrderIsTotal asserts the order on ties the corpus does not carry: one
// class, pks that differ only in their last byte.
func TestOrderIsTotal(t *testing.T) {
	var a, b, c [32]byte
	a[31], b[31], c[31] = 3, 1, 2
	e := warden.Estate{Classes: []warden.Class{{Beings: []warden.Held{
		{Being: a}, {Being: b}, {Being: c},
	}}}}
	got := e.Order().Classes[0].Beings
	if got[0].Being != b || got[1].Being != c || got[2].Being != a {
		t.Fatalf("ordered to %x %x %x", got[0].Being, got[1].Being, got[2].Being)
	}
}

func sameEstate(a, b warden.Estate) bool {
	if len(a.Classes) != len(b.Classes) {
		return false
	}
	for i := range a.Classes {
		if a.Classes[i].Digest != b.Classes[i].Digest {
			return false
		}
		if len(a.Classes[i].Beings) != len(b.Classes[i].Beings) {
			return false
		}
		for j := range a.Classes[i].Beings {
			if a.Classes[i].Beings[j] != b.Classes[i].Beings[j] {
				return false
			}
		}
	}
	return true
}

func readEstate(t *testing.T, raw json.RawMessage) warden.Estate {
	t.Helper()
	var o struct {
		Classes []struct {
			Digest string `json:"digest"`
			Beings []struct {
				Being      string `json:"being"`
				Commitment string `json:"commitment"`
			} `json:"beings"`
		} `json:"classes"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	e := warden.Estate{}
	for _, c := range o.Classes {
		class := warden.Class{Digest: key(t, c.Digest)}
		for _, h := range c.Beings {
			class.Beings = append(class.Beings, warden.Held{
				Being: key(t, h.Being), Commitment: key(t, h.Commitment),
			})
		}
		e.Classes = append(e.Classes, class)
	}
	return e
}

func rawOf(t *testing.T, v corpus.Vector, name string) json.RawMessage {
	t.Helper()
	raw, ok := v.Raw(name)
	if !ok {
		t.Fatalf("the vector carries no %s", name)
	}
	return raw
}

func key(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("a b32 that is %d bytes", len(b))
	}
	var k [32]byte
	copy(k[:], b)
	return k
}
