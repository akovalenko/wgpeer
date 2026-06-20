// Package wgkey implements native WireGuard key handling: curve25519 keypair
// generation, preshared-key generation, and the std-base64 encoding wg uses.
// Native (not shelling out to `wg genkey`) keeps the client zero-deps on a
// phone where wireguard-tools may be absent (spec §6, §14).
package wgkey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyLen is the byte length of a curve25519 key and of a preshared key.
const KeyLen = 32

// Encode renders a 32-byte key as wireguard's standard base64 (44 chars).
func Encode(k [KeyLen]byte) string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Decode parses a wireguard standard-base64 key.
func Decode(s string) ([KeyLen]byte, error) {
	var k [KeyLen]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(b) != KeyLen {
		return k, fmt.Errorf("key has %d bytes, want %d", len(b), KeyLen)
	}
	copy(k[:], b)
	return k, nil
}

// GeneratePrivateKey returns a fresh clamped curve25519 private key
// (32 random bytes, clamped exactly as `wg genkey` does).
func GeneratePrivateKey() ([KeyLen]byte, error) {
	var k [KeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("reading randomness: %w", err)
	}
	clamp(&k)
	return k, nil
}

// PublicKey derives the curve25519 public key from a private key
// (scalar * basepoint).
func PublicKey(priv [KeyLen]byte) ([KeyLen]byte, error) {
	var pub [KeyLen]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("deriving public key: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}

// PublicFromPrivateBase64 derives the base64 public key from a base64 private
// key. Used server-side to advertise its own public key (from [Interface]
// PrivateKey) without shelling out to wg.
func PublicFromPrivateBase64(privB64 string) (string, error) {
	priv, err := Decode(privB64)
	if err != nil {
		return "", err
	}
	pub, err := PublicKey(priv)
	if err != nil {
		return "", err
	}
	return Encode(pub), nil
}

// GeneratePSK returns a fresh 32-byte preshared key (spec §8).
func GeneratePSK() ([KeyLen]byte, error) {
	var k [KeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("reading randomness: %w", err)
	}
	return k, nil
}

func clamp(k *[KeyLen]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}
