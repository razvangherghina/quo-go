// Package arithmetic holds the four algorithms, named once and never
// negotiated: Ed25519 signs, X25519 seals, SHA-256 commits, and AES-256-GCM
// encrypts under a key drawn through HKDF-SHA-256.
//
// No message says which algorithms it used, so there is nothing here to
// select and no suite to carry. Every draw of randomness is taken as an
// argument: nothing in this package reaches for a random source.
package arithmetic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Info is the one constant the seal's key is drawn under. The label and the
// info are one constant, not two, so a key agreed for one purpose can never
// serve another.
const Info = "quo-seal"

// TagSize is the full-length GCM tag, and it is the last bytes of the box.
const TagSize = 16

// SignatureSize is what an Ed25519 signature always is.
const SignatureSize = 64

// Hash is SHA-256, which is every digest in Quo.
func Hash(b []byte) [32]byte { return sha256.Sum256(b) }

// Commit is an heir commitment: the pk of the warden the heir would spend at,
// then the heir's pk, each thirty-two bytes, hashed in that order. A bare hash
// of a key would bind the key and not the place.
func Commit(warden, heir [32]byte) [32]byte {
	var b [64]byte
	copy(b[:32], warden[:])
	copy(b[32:], heir[:])
	return sha256.Sum256(b[:])
}

// SigningKey is the public half of the Ed25519 pair those thirty-two bytes
// mint.
func SigningKey(secret [32]byte) [32]byte {
	var pk [32]byte
	copy(pk[:], ed25519.NewKeyFromSeed(secret[:]).Public().(ed25519.PublicKey))
	return pk
}

// Sign is an Ed25519 signature over the message by that secret.
func Sign(secret [32]byte, message []byte) [SignatureSize]byte {
	var sig [SignatureSize]byte
	copy(sig[:], ed25519.Sign(ed25519.NewKeyFromSeed(secret[:]), message))
	return sig
}

// Verify says whether the signature is that key's over those bytes.
func Verify(pk [32]byte, message []byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pk[:]), message, sig[:])
}

// SealingKey is the padlock those thirty-two bytes mint. The bytes are the
// X25519 private key itself: clamping happens inside the algorithm, and no
// step is added in front of it.
func SealingKey(secret [32]byte) ([32]byte, error) {
	var pk [32]byte
	k, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return pk, err
	}
	copy(pk[:], k.PublicKey().Bytes())
	return pk, nil
}

// Agree is the X25519 shared secret between that private key and that padlock.
func Agree(secret, peer [32]byte) ([32]byte, error) {
	var shared [32]byte
	priv, err := ecdh.X25519().NewPrivateKey(secret[:])
	if err != nil {
		return shared, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return shared, err
	}
	b, err := priv.ECDH(pub)
	if err != nil {
		return shared, err
	}
	copy(shared[:], b)
	return shared, nil
}

// Derive draws forty-four bytes from the shared secret under an empty salt and
// the fixed info: thirty-two of key, then twelve of nonce. The nonce needs no
// randomness of its own, because the key it pairs with is fresh on every
// message by construction.
func Derive(shared [32]byte) (key [32]byte, nonce [12]byte, err error) {
	out, err := hkdf.Key(sha256.New, shared[:], nil, Info, 44)
	if err != nil {
		return key, nonce, err
	}
	copy(key[:], out[:32])
	copy(nonce[:], out[32:])
	return key, nonce, nil
}

// Box seals the plaintext under the key the shared secret derives, binding the
// additional data to it. The tag is the last sixteen bytes of what comes back.
func Box(shared [32]byte, additional, plaintext []byte) ([]byte, error) {
	gcm, nonce, err := mode(shared)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce[:], plaintext, additional), nil
}

// Unbox opens what Box sealed, and refuses anything else.
func Unbox(shared [32]byte, additional, box []byte) ([]byte, error) {
	if len(box) < TagSize {
		return nil, errors.New("arithmetic: no room for a tag")
	}
	gcm, nonce, err := mode(shared)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce[:], box, additional)
}

func mode(shared [32]byte) (cipher.AEAD, [12]byte, error) {
	key, nonce, err := Derive(shared)
	if err != nil {
		return nil, nonce, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nonce, err
	}
	gcm, err := cipher.NewGCM(block)
	return gcm, nonce, err
}
