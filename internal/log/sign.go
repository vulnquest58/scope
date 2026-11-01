// Package log provides signing utilities for the scope evidence journal.
package log

import (
	"crypto/ed25519"
	"crypto/rand"
)

// GenerateKey generates a new Ed25519 key pair for journal signing.
// GenerateKey returns (public, private, error).
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign signs msg with priv and returns the signature.
// Sign uses Ed25519 as specified.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify verifies sig over msg with pub.
// Verify returns true if the signature is valid.
func VerifySig(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

