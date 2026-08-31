package envelope_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/internal/corpus"
	"quo.systems/kit/notation"
)

func TestCorpus(t *testing.T) {
	file, err := corpus.Load("envelope")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the corpus is empty")
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			switch {
			case v.Has("blueprint"):
				checkRecord(t, v)
			case v.Has("payload"):
				checkSignature(t, v)
			case v.Has("envelope"):
				checkEnvelope(t, v)
			default:
				t.Fatalf("no assertion fits this vector")
			}
		})
	}
}

// checkRecord asserts one of the two records both ways, and asserts that the
// shape the corpus wrote is the shape this kit read out of the law.
func checkRecord(t *testing.T, v corpus.Vector) {
	theirs, err := notation.Parse(v.Blueprint)
	if err != nil {
		t.Fatalf("the vector's own blueprint was refused: %v", err)
	}
	if len(theirs.Fields) != 1 || theirs.Fields[0].Answer == nil {
		t.Fatal("a vector names a class with exactly one answering field")
	}
	name := theirs.Fields[0].Answer.Name
	sameShape(t, theirs, name)

	switch name {
	case "say":
		s := readSay(t, v.Value)
		got, err := envelope.EncodeSay(s)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes(t, v, got)

		raw, err := hex.DecodeString(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		back, err := envelope.DecodeSay(raw)
		if err != nil {
			t.Fatalf("refused to decode: %v", err)
		}
		round, err := envelope.EncodeSay(back)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes(t, v, round)
	case "answer":
		a := readAnswer(t, v.Value)
		got, err := envelope.EncodeAnswer(a)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes(t, v, got)

		raw, err := hex.DecodeString(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		back, err := envelope.DecodeAnswer(raw)
		if err != nil {
			t.Fatalf("refused to decode: %v", err)
		}
		round, err := envelope.EncodeAnswer(back)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes(t, v, round)
	default:
		t.Fatalf("the envelope carries no record named %q", name)
	}
}

// sameShape compares a record block the corpus wrote with the one this kit
// holds, member for member. The two records the law fixes in words are the
// one place the agreement rests on the words alone, so a divergence here is a
// divergence in the reading rather than in the bytes.
func sameShape(t *testing.T, theirs *notation.Blueprint, name string) {
	t.Helper()
	ours := mustParse(t, envelope.Shapes)
	for _, block := range theirs.Records {
		mine, ok := ours.Record(block.Name)
		if !ok {
			t.Fatalf("the corpus declares %q and this kit does not", block.Name)
		}
		if len(mine.Members) != len(block.Members) {
			t.Fatalf("%s has %d members here and %d in the corpus", block.Name, len(mine.Members), len(block.Members))
		}
		for i, m := range block.Members {
			if mine.Members[i].Name != m.Name || mine.Members[i].Type.String() != m.Type.String() {
				t.Fatalf("%s field %d is %s %s here and %s %s in the corpus",
					block.Name, i, mine.Members[i].Name, mine.Members[i].Type, m.Name, m.Type)
			}
		}
	}
	if _, ok := ours.Record(name); !ok {
		t.Fatalf("this kit holds no record named %q", name)
	}
}

func checkSignature(t *testing.T, v corpus.Vector) {
	payload := hexOf(t, v, "payload")
	got := arithmetic.Sign(keyOf(t, v, "secret"), payload)
	want, err := v.Text("signature")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("signature\n got %s\nwant %s", hex.EncodeToString(got[:]), want)
	}
	if !arithmetic.Verify(keyOf(t, v, "voice"), payload, got) {
		t.Fatal("its own signature did not verify")
	}
	// The payload the corpus signed is the payload this kit writes — the record
	// byte in front of it included, because that is what the signature covers.
	if _, err := envelope.DecodeSayPayload(payload); err != nil {
		t.Fatalf("refused the payload it signed: %v", err)
	}
}

func checkEnvelope(t *testing.T, v corpus.Vector) {
	message := hexOf(t, v, "envelope")
	padlockSecret := keyOf(t, v, "padlockSecret")

	if v.Refuses {
		if _, err := envelope.OpenSay(padlockSecret, message); err == nil {
			t.Fatal("opened what the corpus refuses")
		}
		return
	}

	s := readSay(t, v.Value)
	got, err := envelope.SealSay(
		keyOf(t, v, "ephemeralSecret"),
		keyOf(t, v, "padlock"),
		keyOf(t, v, "voiceSecret"),
		s,
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := v.Text("envelope")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("envelope\n got %s\nwant %s", hex.EncodeToString(got), want)
	}

	back, err := envelope.OpenSay(padlockSecret, message)
	if err != nil {
		t.Fatalf("refused to open: %v", err)
	}
	round, err := envelope.EncodeSay(back)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := envelope.EncodeSay(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(round, mine) {
		t.Fatalf("opened to a different payload\n got %x\nwant %x", round, mine)
	}
}

// TestAnswerSealsBothWays asserts the answer's own boundary: same encoder,
// signed by the warden's own name, opened back to the same record.
func TestAnswerSealsBothWays(t *testing.T) {
	material := map[string][32]byte{}
	for name, h := range map[string]string{
		"nameSecret":      "196982eee79e80efbc3131c93b99285a38c540c43e7e4fbb8399c260b1ce5103",
		"returnPadlock":   "5a13b7a05e31ae998ad1307217981bb23bb17d277465829edd616e9169c8f46e",
		"returnSecret":    "73c735d14464c99c8412ccff9c0e59cf59fe42b7e925affff2590b8328e46fba",
		"ephemeralSecret": "fcfabee71b7a33993cca5579e6a273ffd1c62cc1749cbf1c9049f599e44f6477",
	} {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		var k [32]byte
		copy(k[:], b)
		material[name] = k
	}

	a := envelope.Answer{
		Warden: arithmetic.SigningKey(material["nameSecret"]),
		Seq:    1,
		Data:   []byte("yes"),
	}
	sealed, err := envelope.SealAnswer(material["ephemeralSecret"], material["returnPadlock"], material["nameSecret"], a)
	if err != nil {
		t.Fatal(err)
	}
	back, err := envelope.OpenAnswer(material["returnSecret"], sealed)
	if err != nil {
		t.Fatal(err)
	}
	if back.Warden != a.Warden || back.Seq != a.Seq || !bytes.Equal(back.Data, a.Data) {
		t.Fatalf("opened to %#v", back)
	}

	turned := append([]byte(nil), sealed...)
	turned[len(turned)-1] ^= 1
	if _, err := envelope.OpenAnswer(material["returnSecret"], turned); err == nil {
		t.Fatal("a turned byte opened")
	}
}

// TestArgumentRecordComesFirst holds the ordering the law rules for a field
// whose argument is a record: within one field, first use runs left to right —
// its arguments in their declared order, then what it answers. The corpus
// carries no such blueprint, so this is asserted from the law's words alone.
func TestArgumentRecordComesFirst(t *testing.T) {
	canonical := "Ship\n  send(to address) label\n\naddress\n  city text\n\nlabel\n  code text\n"
	answerFirst := "Ship\n  send(to address) label\n\nlabel\n  code text\n\naddress\n  city text\n"

	bp := mustParse(t, canonical)
	if bp.Text() != canonical {
		t.Fatalf("printed\n%q\nwant\n%q", bp.Text(), canonical)
	}
	if _, err := notation.Parse(answerFirst); err == nil {
		t.Fatal("accepted the answer's record ahead of the argument's")
	}
}

func readSay(t *testing.T, raw json.RawMessage) envelope.Say {
	t.Helper()
	var o struct {
		Voice      string   `json:"voice"`
		Recipient  string   `json:"recipient"`
		Commitment *string  `json:"commitment"`
		Seq        string   `json:"seq"`
		Padlock    string   `json:"padlock"`
		Hints      []string `json:"hints"`
		Allowance  struct {
			Time string `json:"time"`
			Hops string `json:"hops"`
		} `json:"allowance"`
		Being  *string `json:"being"`
		Method *struct {
			Name string `json:"name"`
			Args string `json:"args"`
		} `json:"method"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	s := envelope.Say{
		Voice:      key(t, o.Voice),
		Recipient:  key(t, o.Recipient),
		Commitment: maybeKey(t, o.Commitment),
		Seq:        number(t, o.Seq),
		Padlock:    key(t, o.Padlock),
		Hints:      o.Hints,
		Allowance:  envelope.Allowance{Time: number(t, o.Allowance.Time), Hops: number(t, o.Allowance.Hops)},
		Being:      maybeKey(t, o.Being),
	}
	if o.Method != nil {
		args, err := hex.DecodeString(o.Method.Args)
		if err != nil {
			t.Fatal(err)
		}
		s.Method = &envelope.Method{Name: o.Method.Name, Args: args}
	}
	return s
}

func readAnswer(t *testing.T, raw json.RawMessage) envelope.Answer {
	t.Helper()
	var o struct {
		Warden string  `json:"warden"`
		Seq    string  `json:"seq"`
		Data   *string `json:"data"`
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	a := envelope.Answer{Warden: key(t, o.Warden), Seq: number(t, o.Seq)}
	if o.Data != nil {
		b, err := hex.DecodeString(*o.Data)
		if err != nil {
			t.Fatal(err)
		}
		a.Data = b
	}
	return a
}

func mustParse(t *testing.T, text string) *notation.Blueprint {
	t.Helper()
	bp, err := notation.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return bp
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

func maybeKey(t *testing.T, s *string) *[32]byte {
	t.Helper()
	if s == nil {
		return nil
	}
	k := key(t, *s)
	return &k
}

func number(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func hexOf(t *testing.T, v corpus.Vector, name string) []byte {
	t.Helper()
	b, err := v.Hex(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keyOf(t *testing.T, v corpus.Vector, name string) [32]byte {
	t.Helper()
	k, err := v.Key(name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func wantBytes(t *testing.T, v corpus.Vector, got []byte) {
	t.Helper()
	if hex.EncodeToString(got) != v.Bytes {
		t.Fatalf("bytes\n got %s\nwant %s", hex.EncodeToString(got), v.Bytes)
	}
}
