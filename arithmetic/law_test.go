package arithmetic_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"quo.systems/kit/arithmetic"
)

// Everything here is asserted from the constitution's own words, under "The
// arithmetic": four algorithms, named once and never negotiated.

func draw(label string) [32]byte { return sha256.Sum256([]byte("quo-go-bench/" + label)) }

// TestNothingReachesForRandomness holds the rule everything else rests on:
// every draw is taken as an argument, so an implementation can be pinned to
// the byte.
func TestNothingReachesForRandomness(t *testing.T) {
	seed := draw("seed")
	if arithmetic.SigningKey(seed) != arithmetic.SigningKey(seed) {
		t.Fatal("a signing key is not a function of its seed")
	}
	one := arithmetic.Sign(seed, []byte("m"))
	two := arithmetic.Sign(seed, []byte("m"))
	if one != two {
		t.Fatal("a signature is not a function of its inputs")
	}
	a, err := arithmetic.Box(draw("shared"), []byte("aad"), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := arithmetic.Box(draw("shared"), []byte("aad"), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("a box is not a function of its inputs, so a nonce came from somewhere")
	}
}

// TestTheCommitmentBindsTheDoorAndNotOnlyTheKey holds the reason the door's
// name is inside the hash: one heir committed at two doors would otherwise be
// one commitment at both, and spending it at either would spend it at both.
func TestTheCommitmentBindsTheDoorAndNotOnlyTheKey(t *testing.T) {
	heir := arithmetic.SigningKey(draw("heir"))
	doorA := arithmetic.SigningKey(draw("doorA"))
	doorB := arithmetic.SigningKey(draw("doorB"))
	if arithmetic.Commit(doorA, heir) == arithmetic.Commit(doorB, heir) {
		t.Fatal("one heir hashes to one commitment at two doors")
	}
	// The order is pinned: the warden first, then the heir.
	if arithmetic.Commit(doorA, heir) == arithmetic.Commit(heir, doorA) {
		t.Fatal("the commitment does not depend on the order of its two halves")
	}
	var b [64]byte
	copy(b[:32], doorA[:])
	copy(b[32:], heir[:])
	if arithmetic.Commit(doorA, heir) != sha256.Sum256(b[:]) {
		t.Fatal("the commitment is not SHA-256 over the two keys concatenated")
	}
}

// TestASignatureIsSixtyFourBytesAndBindsBothKeyAndMessage holds Ed25519's part
// and the one length the envelope depends on.
func TestASignatureIsSixtyFourBytesAndBindsBothKeyAndMessage(t *testing.T) {
	secret := draw("voice")
	pk := arithmetic.SigningKey(secret)
	sig := arithmetic.Sign(secret, []byte("by whose authority"))
	if len(sig) != arithmetic.SignatureSize || arithmetic.SignatureSize != 64 {
		t.Fatalf("a signature is %d bytes", len(sig))
	}
	if !arithmetic.Verify(pk, []byte("by whose authority"), sig) {
		t.Fatal("a key did not verify its own signature")
	}
	if arithmetic.Verify(pk, []byte("by whose authoritz"), sig) {
		t.Fatal("a signature verified over other bytes")
	}
	if arithmetic.Verify(arithmetic.SigningKey(draw("other")), []byte("by whose authority"), sig) {
		t.Fatal("a signature verified under another key")
	}
	turned := sig
	turned[0] ^= 1
	if arithmetic.Verify(pk, []byte("by whose authority"), turned) {
		t.Fatal("a turned signature verified")
	}
}

// TestAgreementIsSymmetricAndTheSecretIsNotASeed holds X25519's part: the
// thirty-two bytes a pair is minted from are the private key itself, and Quo
// adds no step before a standard algorithm.
func TestAgreementIsSymmetricAndTheSecretIsNotASeed(t *testing.T) {
	aSecret, bSecret := draw("a"), draw("b")
	aPub, err := arithmetic.SealingKey(aSecret)
	if err != nil {
		t.Fatal(err)
	}
	bPub, err := arithmetic.SealingKey(bSecret)
	if err != nil {
		t.Fatal(err)
	}
	one, err := arithmetic.Agree(aSecret, bPub)
	if err != nil {
		t.Fatal(err)
	}
	two, err := arithmetic.Agree(bSecret, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatal("the two sides did not agree on one secret")
	}
	// Clamping happens inside the algorithm, so a secret that differs only in
	// the bits clamping would fix still yields the clamped key rather than
	// being refused or hashed first.
	clamped := aSecret
	clamped[0] &= 248
	clamped[31] = (clamped[31] & 127) | 64
	got, err := arithmetic.SealingKey(clamped)
	if err != nil {
		t.Fatal(err)
	}
	if got != aPub {
		t.Fatal("the secret is treated as a seed rather than as the private key")
	}
}

// TestTheDerivationIsPinnedToTheByte holds the whole of HKDF's use: an empty
// salt, one fixed info, forty-four bytes drawn as thirty-two of key then
// twelve of nonce.
func TestTheDerivationIsPinnedToTheByte(t *testing.T) {
	if arithmetic.Info != "quo-seal" {
		t.Fatalf("the info is %q", arithmetic.Info)
	}
	key, nonce, err := arithmetic.Derive(draw("shared"))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 || len(nonce) != 12 {
		t.Fatalf("drew %d of key and %d of nonce", len(key), len(nonce))
	}
	other, otherNonce, err := arithmetic.Derive(draw("otherShared"))
	if err != nil {
		t.Fatal(err)
	}
	if key == other || nonce == otherNonce {
		t.Fatal("two agreements drew one key")
	}
	// The nonce needs no randomness of its own, because the key it pairs with
	// is fresh on every message by construction — so the derivation is a
	// function of the agreement alone.
	again, againNonce, err := arithmetic.Derive(draw("shared"))
	if err != nil {
		t.Fatal(err)
	}
	if again != key || againNonce != nonce {
		t.Fatal("the derivation is not a function of the agreement")
	}
}

// TestTheAdditionalDataBindsTheLidToTheBox holds why the ephemeral key is the
// additional authenticated data: it is the one thing outside the seal, so the
// lid and the box cannot be mixed and matched.
func TestTheAdditionalDataBindsTheLidToTheBox(t *testing.T) {
	shared := draw("shared")
	lid := draw("lid")
	box, err := arithmetic.Box(shared, lid[:], []byte("cargo"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arithmetic.Unbox(shared, lid[:], box); err != nil {
		t.Fatalf("its own lid did not open it: %v", err)
	}
	other := draw("otherLid")
	if _, err := arithmetic.Unbox(shared, other[:], box); err == nil {
		t.Fatal("another lid opened the box")
	}
	if _, err := arithmetic.Unbox(shared, nil, box); err == nil {
		t.Fatal("no lid at all opened the box")
	}
	if _, err := arithmetic.Unbox(draw("otherShared"), lid[:], box); err == nil {
		t.Fatal("another agreement opened the box")
	}
}

// TestAnEmptyPlaintextIsStillATag holds the shape at its smallest, because a
// field that answers nothing answers zero bytes and that still has to seal.
func TestAnEmptyPlaintextIsStillATag(t *testing.T) {
	box, err := arithmetic.Box(draw("shared"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != arithmetic.TagSize {
		t.Fatalf("an empty box is %d bytes, want %d", len(box), arithmetic.TagSize)
	}
	plain, err := arithmetic.Unbox(draw("shared"), nil, box)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 0 {
		t.Fatalf("it opened to %d bytes", len(plain))
	}
	if _, err := arithmetic.Unbox(draw("shared"), nil, box[:len(box)-1]); err == nil {
		t.Fatal("a box shorter than its tag opened")
	}
}

// TestHashIsSHA256 holds the one hash Quo has, because every digest and every
// commitment is this and nothing negotiates it.
func TestHashIsSHA256(t *testing.T) {
	if arithmetic.Hash([]byte("abc")) != sha256.Sum256([]byte("abc")) {
		t.Fatal("Hash is not SHA-256")
	}
}
