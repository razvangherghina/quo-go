package arithmetic_test

import (
	"encoding/hex"
	"sort"
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/internal/corpus"
)

// A signing pair: the seed, and the pk the algorithm derives from it.
var signing = [][2]string{
	{"wardenNameSecret", "wardenName"},
	{"voiceSecret", "voice"},
	{"voiceHeirSecret", "voiceHeir"},
	{"successorSecret", "successor"},
	{"nextHeirSecret", "nextHeir"},
}

// A sealing pair: the private key itself, and its public half.
var sealing = [][2]string{
	{"padlockSecret", "padlock"},
	{"returnPadlockSecret", "returnPadlock"},
	{"ephemeralSecret", "ephemeral"},
}

// A commitment: the warden it would be spent at, the heir, and the digest.
// Every heir in this file spends at the one door, so each hashes under
// wardenName.
var commitments = [][3]string{
	{"wardenName", "wardenHeir", "wardenCommitment"},
	{"wardenName", "voiceHeir", "voiceHeirCommitment"},
	{"wardenName", "beingHeir", "beingCommitment"},
	{"wardenName", "nextHeir", "nextHeirCommitment"},
}

// Names the file fixes without giving anything to derive them from.
var pinned = []string{
	"wardenNameSecret",
	"voiceSecret",
	"voiceHeirSecret",
	"nextHeirSecret",
	"successorSecret",
	"padlockSecret",
	"returnPadlockSecret",
	"ephemeralSecret",
	"wardenHeir",
	"being",
	"beingHeir",
}

func material(t *testing.T) corpus.Material {
	t.Helper()
	m, err := corpus.LoadMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if m.Area != "material" {
		t.Fatalf("area is %q rather than material", m.Area)
	}
	if m.Encoding != "hex" {
		t.Fatalf("encoding is %q rather than hex", m.Encoding)
	}
	return m
}

func TestEveryEntryInTheMaterialIsThirtyTwoBytes(t *testing.T) {
	m := material(t)
	for name := range m.Keys {
		b, err := hex.DecodeString(m.Keys[name])
		if err != nil {
			t.Fatalf("%s is not hex: %v", name, err)
		}
		if len(b) != 32 {
			t.Fatalf("%s is %d bytes rather than thirty-two", name, len(b))
		}
	}
}

func TestEveryKeyInTheMaterialIsDerivedHereOrDeclaredPinned(t *testing.T) {
	m := material(t)
	accounted := map[string]bool{}
	for _, pair := range signing {
		accounted[pair[0]], accounted[pair[1]] = true, true
	}
	for _, pair := range sealing {
		accounted[pair[0]], accounted[pair[1]] = true, true
	}
	for _, one := range commitments {
		accounted[one[0]], accounted[one[1]], accounted[one[2]] = true, true, true
	}
	for _, name := range pinned {
		accounted[name] = true
	}

	var unaccounted, absent []string
	for name := range m.Keys {
		if !accounted[name] {
			unaccounted = append(unaccounted, name)
		}
	}
	for name := range accounted {
		if _, ok := m.Keys[name]; !ok {
			absent = append(absent, name)
		}
	}
	sort.Strings(unaccounted)
	sort.Strings(absent)
	if len(unaccounted) > 0 {
		t.Fatalf("the material carries %v and nothing here derives or pins them", unaccounted)
	}
	if len(absent) > 0 {
		t.Fatalf("this test names %v and the material carries no such key", absent)
	}
}

func TestTheMaterialsSigningPairs(t *testing.T) {
	m := material(t)
	for _, pair := range signing {
		secret, err := m.Key(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		pk, err := m.Key(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if arithmetic.SigningKey(secret) != pk {
			t.Fatalf("%s is not the Ed25519 pk of %s", pair[1], pair[0])
		}
	}
}

func TestTheMaterialsSealingPairs(t *testing.T) {
	m := material(t)
	for _, pair := range sealing {
		secret, err := m.Key(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		pk, err := m.Key(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		derived, err := arithmetic.SealingKey(secret)
		if err != nil {
			t.Fatal(err)
		}
		if derived != pk {
			t.Fatalf("%s is not the X25519 pk of %s", pair[1], pair[0])
		}
	}
}

func TestEveryCommitmentDerivesFromKeysTheCorpusPublishes(t *testing.T) {
	m := material(t)
	for _, one := range commitments {
		warden, err := m.Key(one[0])
		if err != nil {
			t.Fatal(err)
		}
		heir, err := m.Key(one[1])
		if err != nil {
			t.Fatal(err)
		}
		want, err := m.Key(one[2])
		if err != nil {
			t.Fatal(err)
		}
		if arithmetic.Commit(warden, heir) != want {
			t.Fatalf("%s is not %s then %s, hashed", one[2], one[0], one[1])
		}
	}
}
