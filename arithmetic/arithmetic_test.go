package arithmetic_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/internal/corpus"
)

func TestCorpus(t *testing.T) {
	file, err := corpus.Load("arithmetic")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the corpus is empty")
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			switch {
			case v.Has("hash"):
				checkHash(t, v)
			case v.Has("commitment"):
				checkCommit(t, v)
			case v.Has("signature"):
				checkSignature(t, v)
			case v.Has("nonce"):
				checkDerive(t, v)
			case v.Has("ciphertext"):
				checkBox(t, v)
			case v.Has("shared"):
				checkAgree(t, v)
			case v.Has("pk"):
				checkPair(t, v)
			default:
				t.Fatalf("no assertion fits this vector")
			}
		})
	}
}

func checkHash(t *testing.T, v corpus.Vector) {
	in := hexOf(t, v, "input")
	got := arithmetic.Hash(in)
	wantHex(t, v, "hash", got[:])
}

func checkCommit(t *testing.T, v corpus.Vector) {
	warden := keyOf(t, v, "warden")
	heir := keyOf(t, v, "heir")
	got := arithmetic.Commit(warden, heir)
	wantHex(t, v, "commitment", got[:])
}

func checkPair(t *testing.T, v corpus.Vector) {
	secret := keyOf(t, v, "secret")
	var got [32]byte
	if strings.Contains(v.Name, "Ed25519") {
		got = arithmetic.SigningKey(secret)
	} else {
		var err error
		if got, err = arithmetic.SealingKey(secret); err != nil {
			t.Fatal(err)
		}
	}
	wantHex(t, v, "pk", got[:])
}

func checkSignature(t *testing.T, v corpus.Vector) {
	message := hexOf(t, v, "message")
	voice := keyOf(t, v, "voice")
	var sig [arithmetic.SignatureSize]byte
	copy(sig[:], hexOf(t, v, "signature"))

	if v.Refuses {
		if arithmetic.Verify(voice, message, sig) {
			t.Fatal("verified what the corpus refuses")
		}
		return
	}
	got := arithmetic.Sign(keyOf(t, v, "secret"), message)
	wantHex(t, v, "signature", got[:])
	if !arithmetic.Verify(voice, message, got) {
		t.Fatal("its own signature did not verify")
	}
}

func checkAgree(t *testing.T, v corpus.Vector) {
	got, err := arithmetic.Agree(keyOf(t, v, "secret"), keyOf(t, v, "pk"))
	if err != nil {
		t.Fatal(err)
	}
	wantHex(t, v, "shared", got[:])
}

func checkDerive(t *testing.T, v corpus.Vector) {
	info, err := v.Hex("info")
	if err != nil {
		t.Fatal(err)
	}
	if string(info) != arithmetic.Info {
		t.Fatalf("the info is %q, not %q", info, arithmetic.Info)
	}
	salt, err := v.Hex("salt")
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != 0 {
		t.Fatalf("the salt is %d bytes rather than empty", len(salt))
	}

	key, nonce, err := arithmetic.Derive(keyOf(t, v, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	wantHex(t, v, "key", key[:])
	wantHex(t, v, "nonce", nonce[:])
}

func checkBox(t *testing.T, v corpus.Vector) {
	shared := keyOf(t, v, "shared")
	additional := hexOf(t, v, "additional")
	ciphertext := hexOf(t, v, "ciphertext")

	if v.Refuses {
		if _, err := arithmetic.Unbox(shared, additional, ciphertext); err == nil {
			t.Fatal("opened what the corpus refuses")
		}
		return
	}
	plaintext := hexOf(t, v, "plaintext")
	got, err := arithmetic.Box(shared, additional, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	wantHex(t, v, "ciphertext", got)

	back, err := arithmetic.Unbox(shared, additional, ciphertext)
	if err != nil {
		t.Fatalf("refused to open: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("opened to %x, want %x", back, plaintext)
	}
}

// TestTagRidesLast holds the one placement the law had to rule: the
// ciphertext first, the tag after it, sixteen bytes at full length.
func TestTagRidesLast(t *testing.T) {
	var shared [32]byte
	plaintext := []byte("by whose authority")
	box, err := arithmetic.Box(shared, nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != len(plaintext)+arithmetic.TagSize {
		t.Fatalf("the box is %d bytes, want %d", len(box), len(plaintext)+arithmetic.TagSize)
	}
	turned := append([]byte(nil), box...)
	turned[len(turned)-1] ^= 1
	if _, err := arithmetic.Unbox(shared, nil, turned); err == nil {
		t.Fatal("a turned last byte opened, so the tag is not there")
	}
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

func wantHex(t *testing.T, v corpus.Vector, name string, got []byte) {
	t.Helper()
	want, err := v.Text(name)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s\n got %s\nwant %s", name, hex.EncodeToString(got), want)
	}
}
