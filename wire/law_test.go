package wire_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// Everything here is asserted from the constitution's own words, under "The
// wire encoding of the types" — the section that gives each type exactly one
// way of being written on the wire. The corpus pins bytes; these pin the rules, and a
// refusal is asserted as strictly as an acceptance.

// under parses a one-field class and hands back its answer type, which is the
// type the case is about.
func under(t *testing.T, spelling string) (*notation.Blueprint, notation.Type) {
	t.Helper()
	bp, err := notation.Parse("Probe\n  probe() " + spelling + "\n")
	if err != nil {
		t.Fatalf("the case's own blueprint was refused: %v", err)
	}
	return bp, *bp.Fields[0].Answer
}

// writes holds a value's one spelling.
func writes(t *testing.T, spelling string, v any, want string) {
	t.Helper()
	bp, ty := under(t, spelling)
	got, err := wire.Encode(bp, ty, v)
	if err != nil {
		t.Fatalf("%s: refused to encode: %v", spelling, err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s\n got %s\nwant %s", spelling, hex.EncodeToString(got), want)
	}
	// One way of being written means the bytes read back to the same value and
	// write out again unchanged.
	back, err := wire.Decode(bp, ty, got)
	if err != nil {
		t.Fatalf("%s: refused its own bytes: %v", spelling, err)
	}
	again, err := wire.Encode(bp, ty, back)
	if err != nil {
		t.Fatalf("%s: refused to re-encode: %v", spelling, err)
	}
	if !bytes.Equal(again, got) {
		t.Fatalf("%s: the round trip changed the bytes", spelling)
	}
}

// rejects holds bytes a decoder must refuse. Malformed bytes are the
// receiver's to refuse, and the refusal is silence.
func rejects(t *testing.T, why, spelling, hexBytes string) {
	t.Helper()
	bp, ty := under(t, spelling)
	b, err := hex.DecodeString(hexBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.Decode(bp, ty, b); err == nil {
		t.Errorf("accepted %s: %s as %s", why, hexBytes, spelling)
	}
}

// TestBoolIsOneByteZeroOrOne holds the type and its one refusal: a byte that
// is neither is not described here, so a receiver meeting one refuses.
func TestBoolIsOneByteZeroOrOne(t *testing.T) {
	writes(t, "bool", false, "00")
	writes(t, "bool", true, "01")
	rejects(t, "a bool that is neither zero nor one", "bool", "02")
	rejects(t, "a bool with no byte at all", "bool", "")
	rejects(t, "a bool with a byte left over", "bool", "0100")
}

// TestIntIsEightBytesSignedMostSignificantFirst holds the whole range, because
// a kit that clamped or widened would be a kit that reads another protocol.
func TestIntIsEightBytesSignedMostSignificantFirst(t *testing.T) {
	writes(t, "int", int64(0), "0000000000000000")
	writes(t, "int", int64(1), "0000000000000001")
	writes(t, "int", int64(-1), "ffffffffffffffff")
	writes(t, "int", int64(256), "0000000000000100")
	writes(t, "int", int64(1<<62), "4000000000000000")
	writes(t, "int", int64(-1<<63), "8000000000000000")
	writes(t, "int", int64(1<<63-1), "7fffffffffffffff")
	rejects(t, "an int of seven bytes", "int", "00000000000001")
	rejects(t, "an int of nine bytes", "int", "000000000000000100")
}

// TestTextCountsBytesRatherThanCharacters holds the only count a decoder can
// act on before it has decoded anything.
func TestTextCountsBytesRatherThanCharacters(t *testing.T) {
	writes(t, "text", "", "0000000000000000")
	writes(t, "text", "hi", "00000000000000026869")
}

// TestAnEncoderRefusesWhatNoDecoderMayRead holds the encoder's half of the
// UTF-8 rule: a kit may not write what no kit may read. A Go string is bytes
// and can hold what is no code point at all, so the refusal has to be made
// rather than inherited from the language.
func TestAnEncoderRefusesWhatNoDecoderMayRead(t *testing.T) {
	bp, ty := under(t, "text")
	for _, s := range []string{"\xff", "a\x80b", "\xed\xa0\x80"} {
		if _, err := wire.Encode(bp, ty, s); err == nil {
			t.Errorf("wrote text that is not UTF-8: %q", s)
		}
		// And what the encoder refuses to write, the decoder refuses to read.
		b := append(make([]byte, 8), s...)
		b[7] = byte(len(s))
		if _, err := wire.Decode(bp, ty, b); err == nil {
			t.Errorf("read text that is not UTF-8: %q", s)
		}
	}
	// The same refusal guards the hints, which are the one [text] this package
	// writes without walking the general list.
	if _, err := wire.Encode(bp, notation.Type{Kind: notation.KindCard},
		wire.Card{Hints: []string{"\xff"}}); err == nil {
		t.Error("wrote a hint that is not UTF-8")
	}
}

// TestATextIsCarriedAsGivenAndNeverNormalised holds that two normalisation
// forms are two values: a kit that repaired or normalised would have forged a
// second spelling of a thing this protocol names by the hash of its bytes.
func TestATextIsCarriedAsGivenAndNeverNormalised(t *testing.T) {
	composed := "é"    // é as one code point
	decomposed := "é" // and as e plus a combining accent
	// A byte order mark inside a value is ordinary content, at the head as
	// much as in the middle. It is built from its bytes because a Go source
	// file may not carry one of its own.
	bom := string([]byte{0xEF, 0xBB, 0xBF})
	markInside := bom + "hi" + bom + "no"

	bp, ty := under(t, "text")
	seen := map[string]bool{}
	for _, s := range []string{composed, decomposed, markInside} {
		got, err := wire.Encode(bp, ty, s)
		if err != nil {
			t.Fatalf("%q was refused: %v", s, err)
		}
		if !bytes.Equal(got[8:], []byte(s)) {
			t.Fatalf("%q was written as %q", s, got[8:])
		}
		back, err := wire.Decode(bp, ty, got)
		if err != nil {
			t.Fatalf("%q would not read back: %v", s, err)
		}
		// The mark is kept rather than stripped: a decoder that ate it would
		// hand back a second spelling of what arrived.
		if back.(string) != s {
			t.Fatalf("%q came back as %q", s, back)
		}
		seen[hex.EncodeToString(got)] = true
	}
	if len(seen) != 3 {
		t.Fatal("two of these three values ride the same bytes")
	}
}

// TestTextIsUTF8AfterItsLength holds the encoding and the length together, on
// a string whose bytes and characters differ.
func TestTextIsUTF8AfterItsLength(t *testing.T) {
	// Four characters, seven bytes.
	s := "héllo"[:0] + "aé漢"
	bp, ty := under(t, "text")
	got, err := wire.Encode(bp, ty, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8+len(s) {
		t.Fatalf("the length does not count bytes: %d for %d", len(got)-8, len(s))
	}
	if !bytes.Equal(got[8:], []byte(s)) {
		t.Fatal("the text is not its UTF-8 bytes")
	}
	if got[7] != byte(len(s)) {
		t.Fatalf("the count is %d, want %d", got[7], len(s))
	}
	rejects(t, "a text whose length runs past the bytes", "text", "0000000000000005616263")
	rejects(t, "a negative length", "text", "ffffffffffffffff")
}

// TestBytesIsALengthAndThenTheBytes holds the type, and holds that a present
// but empty value is a legal one.
func TestBytesIsALengthAndThenTheBytes(t *testing.T) {
	writes(t, "bytes", []byte{}, "0000000000000000")
	writes(t, "bytes", []byte{0xde, 0xad}, "0000000000000002dead")
	rejects(t, "a count beyond the bytes that remain", "bytes", "0000000000000004dead")
	rejects(t, "a negative length", "bytes", "8000000000000000")
	rejects(t, "bytes left over after a well-formed value", "bytes", "000000000000000100ff")
}

// TestB32IsThirtyTwoBytesWithNoLength holds that it never has another size, so
// a length in front would be a byte an attacker may vary at no cost.
func TestB32IsThirtyTwoBytesWithNoLength(t *testing.T) {
	var k [32]byte
	for i := range k {
		k[i] = byte(i)
	}
	writes(t, "b32", k, hex.EncodeToString(k[:]))
	rejects(t, "a b32 of thirty-one bytes", "b32", strings.Repeat("00", 31))
	rejects(t, "a b32 of thirty-three bytes", "b32", strings.Repeat("00", 33))
}

// TestBeingRidesExactlyAsAB32 holds the one specialised b32: a pk and nothing
// more, the same thirty-two bare bytes.
func TestBeingRidesExactlyAsAB32(t *testing.T) {
	var k [32]byte
	k[0] = 0xaa
	bpA, tyA := under(t, "b32")
	bpB, tyB := under(t, "being")
	a, err := wire.Encode(bpA, tyA, k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := wire.Encode(bpB, tyB, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("a being and a b32 do not ride identically")
	}
}

// TestInvitationIsTheFiveThingsInAFixedOrder holds the layout the law
// writes out, and holds it by bytes rather than by structure.
func TestInvitationIsTheFiveThingsInAFixedOrder(t *testing.T) {
	inv := wire.Invitation{
		Warden:     fill(1),
		Commitment: fill(2),
		Padlock:    fill(3),
		Heir:       fill(4),
		HeirSecret: fill(5),
		Hints:      []string{"a"},
	}
	want := strings.Repeat("01", 32) + strings.Repeat("02", 32) + strings.Repeat("03", 32) +
		strings.Repeat("04", 32) + strings.Repeat("05", 32) +
		"0000000000000001" + "000000000000000161"
	writes(t, "invitation", inv, want)

	// Five keys with no lengths, then the hints as a list of text.
	rejects(t, "an invitation one key short", "invitation", strings.Repeat("00", 128)+"0000000000000000")
}

// TestCardIsTheFourThingsInAFixedOrder holds the card's layout by bytes: the
// warden pk, its heir commitment and the padlock, thirty-two bytes each with
// no lengths, then the hints as [text].
func TestCardIsTheFourThingsInAFixedOrder(t *testing.T) {
	card := wire.Card{
		Warden:     fill(1),
		Commitment: fill(2),
		Padlock:    fill(3),
		Hints:      []string{"a"},
	}
	want := strings.Repeat("01", 32) + strings.Repeat("02", 32) + strings.Repeat("03", 32) +
		"0000000000000001" + "000000000000000161"
	writes(t, "card", card, want)

	// No hints at all is an empty list, not an absent one: a card is four
	// things and the fourth is a list.
	writes(t, "card", wire.Card{Warden: fill(1), Commitment: fill(2), Padlock: fill(3)},
		strings.Repeat("01", 32)+strings.Repeat("02", 32)+strings.Repeat("03", 32)+
			"0000000000000000")

	rejects(t, "a card one key short", "card", strings.Repeat("00", 64)+"0000000000000000")
	rejects(t, "a card whose hints run past the bytes that remain", "card",
		strings.Repeat("00", 96)+"0000000000000001")
	rejects(t, "a byte left over after a well-formed card", "card",
		strings.Repeat("00", 96)+"0000000000000000"+"00")
}

// TestACardIsAnInvitationWithTheKeypairStruckOut holds the sentence the law
// writes: the fields a card keeps ride exactly as they ride in an invitation.
// So a card's bytes are an invitation's with the sixty-four bytes of keypair
// cut out of the middle, and nothing else moves.
func TestACardIsAnInvitationWithTheKeypairStruckOut(t *testing.T) {
	hints := []string{"https://one.example", "quo://two"}
	invBp, invTy := under(t, "invitation")
	inv, err := wire.Encode(invBp, invTy, wire.Invitation{
		Warden:     fill(1),
		Commitment: fill(2),
		Padlock:    fill(3),
		Heir:       fill(4),
		HeirSecret: fill(5),
		Hints:      hints,
	})
	if err != nil {
		t.Fatal(err)
	}
	cardBp, cardTy := under(t, "card")
	card, err := wire.Encode(cardBp, cardTy, wire.Card{
		Warden:     fill(1),
		Commitment: fill(2),
		Padlock:    fill(3),
		Hints:      hints,
	})
	if err != nil {
		t.Fatal(err)
	}
	struck := append(append([]byte{}, inv[:96]...), inv[160:]...)
	if !bytes.Equal(card, struck) {
		t.Fatalf("a card is not the invitation with the keypair struck out\n got %x\nwant %x", card, struck)
	}
}

// fill is a key of one repeated byte, so a layout can be read off the hex.
func fill(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// TestAListIsACountAndThenThatManyItems holds the count in front, and holds
// that a count beyond the bytes that remain is refused rather than truncated.
func TestAListIsACountAndThenThatManyItems(t *testing.T) {
	writes(t, "[bool]", []any{}, "0000000000000000")
	writes(t, "[bool]", []any{true, false}, "00000000000000020100")
	rejects(t, "a count beyond the bytes that remain", "[bool]", "000000000000000401")
	rejects(t, "a negative count", "[bool]", "ffffffffffffffff")
	rejects(t, "an item left over after the count is met", "[bool]", "00000000000000010101")
}

// TestAnOptionalIsOneMarkerByte holds the marker and its refusal: a byte that
// is neither zero nor one is one of the four the law names outright.
func TestAnOptionalIsOneMarkerByte(t *testing.T) {
	writes(t, "int?", nil, "00")
	writes(t, "int?", int64(7), "010000000000000007")
	rejects(t, "a marker that is neither present nor absent", "int?", "02")
	rejects(t, "an absent optional with a value after it", "int?", "000000000000000007")
}

// TestAnAbsentBytesIsNotAnEmptyBytes holds two different messages: a language
// that conflates nil with empty will send the wrong one.
func TestAnAbsentBytesIsNotAnEmptyBytes(t *testing.T) {
	bp, ty := under(t, "bytes?")
	absent, err := wire.Encode(bp, ty, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := wire.Encode(bp, ty, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(absent, empty) {
		t.Fatal("an absent bytes and a present empty one ride the same")
	}
	if hex.EncodeToString(absent) != "00" {
		t.Fatalf("absent is %s", hex.EncodeToString(absent))
	}
	if hex.EncodeToString(empty) != "010000000000000000" {
		t.Fatalf("present and empty is %s", hex.EncodeToString(empty))
	}
}

// TestARecordCarriesNoNames holds that the blueprint already said them and its
// digest is agreed, so a record is its fields in declared order and nothing
// else.
func TestARecordCarriesNoNames(t *testing.T) {
	bp, err := notation.Parse("Probe\n  probe() r\n\nr\n  first bool\n  second int\n")
	if err != nil {
		t.Fatal(err)
	}
	ty := *bp.Fields[0].Answer
	got, err := wire.Encode(bp, ty, map[string]any{"first": true, "second": int64(2)})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "010000000000000002" {
		t.Fatalf("got %s", hex.EncodeToString(got))
	}
	if _, err := wire.Decode(bp, ty, append(got, 0)); err == nil {
		t.Fatal("accepted a byte left over after a well-formed record")
	}
}

// TestARecordsMemberOrderIsTheDeclaredOrder holds that reordering the members
// is a different record rather than the same one written differently.
func TestARecordsMemberOrderIsTheDeclaredOrder(t *testing.T) {
	one, err := notation.Parse("Probe\n  probe() r\n\nr\n  a bool\n  b int\n")
	if err != nil {
		t.Fatal(err)
	}
	two, err := notation.Parse("Probe\n  probe() r\n\nr\n  b int\n  a bool\n")
	if err != nil {
		t.Fatal(err)
	}
	v := map[string]any{"a": true, "b": int64(1)}
	x, err := wire.Encode(one, *one.Fields[0].Answer, v)
	if err != nil {
		t.Fatal(err)
	}
	y, err := wire.Encode(two, *two.Fields[0].Answer, v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(x, y) {
		t.Fatal("two member orders produced one encoding")
	}
}

// TestTheCombinatorsComposeMechanically holds that the encodings compose, so
// refusing a composition would be the opinion.
func TestTheCombinatorsComposeMechanically(t *testing.T) {
	writes(t, "[int?]", []any{nil, int64(1)}, "0000000000000002"+"00"+"010000000000000001")
	writes(t, "[bool]?", nil, "00")
	writes(t, "[bool]?", []any{true}, "01"+"0000000000000001"+"01")
	writes(t, "[[bool]]", []any{[]any{true}, []any{}},
		"0000000000000002"+"000000000000000101"+"0000000000000000")
}

// TestEveryLengthIsWrittenTheWayAnIntIs holds the one rule that saves a
// decoder from a second integer format.
func TestEveryLengthIsWrittenTheWayAnIntIs(t *testing.T) {
	bp, ty := under(t, "text")
	got, err := wire.Encode(bp, ty, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:8]) != "0000000000000004" {
		t.Fatalf("the length is %s", hex.EncodeToString(got[:8]))
	}
}
