package notation

import "crypto/sha256"

// Digest is a blueprint's identity: SHA-256 over its canonical text.
func (b *Blueprint) Digest() [32]byte {
	return sha256.Sum256([]byte(b.Text()))
}
