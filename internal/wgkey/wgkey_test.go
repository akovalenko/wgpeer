package wgkey

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(Encode(k))
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Errorf("round trip changed the key")
	}
}

func TestPrivateKeyClamped(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Errorf("key not clamped: [0]=%08b [31]=%08b", k[0], k[31])
	}
}

func TestDecodeRejectsBadKeys(t *testing.T) {
	if _, err := Decode("not base64!!!"); err == nil {
		t.Errorf("expected error for bad base64")
	}
	if _, err := Decode("YWJj"); err == nil { // "abc" — too short
		t.Errorf("expected error for short key")
	}
}

// TestPublicKeyMatchesWg cross-checks our native curve25519 derivation against
// wireguard-tools, so the two can never disagree. Skips if `wg` is absent.
func TestPublicKeyMatchesWg(t *testing.T) {
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg not installed")
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privB64 := Encode(priv)

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privB64 + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("wg pubkey: %v", err)
	}
	want := strings.TrimSpace(string(out))

	got, err := PublicFromPrivateBase64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("public key mismatch:\n  ours: %s\n  wg:   %s", got, want)
	}
}
