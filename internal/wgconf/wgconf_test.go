package wgconf

import (
	"net/netip"
	"testing"
)

// canonical is already in the tool's canonical form, so Serialize(Parse(x))
// must reproduce it byte-for-byte. It also exercises lead/body comment
// preservation on the second peer (spec §7 + comment-preservation addendum).
const canonical = `[Interface]
PrivateKey = SERVERPRIVATEKEY
ListenPort = 51820

# name: alice
[Peer]
PublicKey = ALICEPUBKEY
AllowedIPs = 10.10.0.2/32
# trailing alice note

# lead for bob
# name: bob
[Peer]
PublicKey = BOBPUBKEY
PresharedKey = BOBPSK
AllowedIPs = 10.10.0.3/32
`

func TestRoundTripIdempotent(t *testing.T) {
	c, err := Parse([]byte(canonical))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := string(c.Serialize())
	if got != canonical {
		t.Errorf("Serialize(Parse(canonical)) not byte-identical.\n--- got ---\n%s\n--- want ---\n%s", got, canonical)
	}
	// Idempotency: a second round trip must equal the first.
	c2, err := Parse(c.Serialize())
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	if string(c2.Serialize()) != got {
		t.Errorf("Serialize not idempotent")
	}
}

func TestParseFields(t *testing.T) {
	c, err := Parse([]byte(canonical))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("got %d peers, want 2", len(c.Peers))
	}
	alice := c.Peers[0]
	if alice.Name != "alice" || alice.PublicKey != "ALICEPUBKEY" {
		t.Errorf("alice = %+v", alice)
	}
	if alice.PresharedKey != "" {
		t.Errorf("alice should have no PSK, got %q", alice.PresharedKey)
	}
	if len(alice.AllowedIPs) != 1 || alice.AllowedIPs[0] != netip.MustParsePrefix("10.10.0.2/32") {
		t.Errorf("alice AllowedIPs = %v", alice.AllowedIPs)
	}
	if len(alice.BodyComments) != 1 || alice.BodyComments[0] != "# trailing alice note" {
		t.Errorf("alice BodyComments = %v", alice.BodyComments)
	}
	bob := c.Peers[1]
	if bob.Name != "bob" || bob.PresharedKey != "BOBPSK" {
		t.Errorf("bob = %+v", bob)
	}
	if len(bob.LeadComments) != 1 || bob.LeadComments[0] != "# lead for bob" {
		t.Errorf("bob LeadComments = %v", bob.LeadComments)
	}
}

func TestHeaderVerbatim(t *testing.T) {
	// The opinionated [Interface] block (PreUp/PostUp/ip rule) must survive untouched.
	const src = `[Interface]
Address = 10.10.0.1/24
PrivateKey = K
ListenPort = 51820
# upstream is wg-over-vxlan, keep MTU
MTU = 1340
PreUp = ip rule add ...
PostUp = iptables -t mangle ...

# name: x
[Peer]
PublicKey = XPUB
AllowedIPs = 10.10.0.9/32
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := `[Interface]
Address = 10.10.0.1/24
PrivateKey = K
ListenPort = 51820
# upstream is wg-over-vxlan, keep MTU
MTU = 1340
PreUp = ip rule add ...
PostUp = iptables -t mangle ...

`
	if c.Header != want {
		t.Errorf("header not verbatim.\n--- got ---\n%q\n--- want ---\n%q", c.Header, want)
	}
	if pk := c.InterfacePrivateKey(); pk != "K" {
		t.Errorf("InterfacePrivateKey = %q, want K", pk)
	}
}

func TestNormaliseMessyPeer(t *testing.T) {
	// Tolerant parse: fields out of order, no spaces, unknown Endpoint key, bare IP.
	const src = `[Interface]
PrivateKey = K
[Peer]
AllowedIPs=10.10.0.5
Endpoint = 1.2.3.4:51820
PublicKey=MESSY
`
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	const want = `[Interface]
PrivateKey = K

[Peer]
PublicKey = MESSY
AllowedIPs = 10.10.0.5/32
`
	if got := string(c.Serialize()); got != want {
		t.Errorf("normalise.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestNoPeers(t *testing.T) {
	const src = "[Interface]\nPrivateKey = K\n"
	c, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Peers) != 0 {
		t.Fatalf("got %d peers", len(c.Peers))
	}
	if c.Header != src {
		t.Errorf("header = %q, want %q", c.Header, src)
	}
}

func TestFindAndRemove(t *testing.T) {
	c, _ := Parse([]byte(canonical))
	if !c.NameExists("bob") || c.NameExists("nobody") {
		t.Errorf("NameExists wrong")
	}
	removed, ok := c.RemoveByName("alice")
	if !ok || removed.PublicKey != "ALICEPUBKEY" {
		t.Errorf("RemoveByName = %+v, %v", removed, ok)
	}
	if len(c.Peers) != 1 || c.Peers[0].Name != "bob" {
		t.Errorf("after remove: %+v", c.Peers)
	}
	if _, ok := c.RemoveByName("ghost"); ok {
		t.Errorf("RemoveByName ghost should fail")
	}
}

func TestValidPeerName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"alice", true},
		{"для Васи", true},       // unicode + internal space
		{"bob's phone #2", true}, // punctuation is fine
		{"", false},              // empty
		{"a\nb", false},          // newline — the injection vector
		{"a\r\n[Peer]", false},   // CRLF injection attempt
		{"tab\there", false},     // other control char
		{" leading", false},      // leading whitespace
		{"trailing ", false},     // trailing whitespace
	}
	for _, tt := range tests {
		if err := ValidPeerName(tt.name); (err == nil) != tt.ok {
			t.Errorf("ValidPeerName(%q) err=%v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

// TestNameInjectionCannotForge proves a newline-bearing name, if it ever
// reached Serialize, would forge a [Peer] block — which is exactly why
// ValidPeerName rejects it upstream.
func TestNameInjectionCannotForge(t *testing.T) {
	evil := "evil\n[Peer]\nPublicKey = ATTACKER\nAllowedIPs = 0.0.0.0/0"
	if ValidPeerName(evil) == nil {
		t.Fatal("ValidPeerName must reject a newline-bearing name")
	}
}

func TestAllocateIP(t *testing.T) {
	tests := []struct {
		name     string
		subnet   string
		reserved []string
		used     []string // peer AllowedIPs
		want     string
		wantErr  bool
	}{
		{
			name:     "next free skips reserved and used",
			subnet:   "10.10.0.0/24",
			reserved: []string{"10.10.0.1"},
			used:     []string{"10.10.0.2/32", "10.10.0.3/32"},
			want:     "10.10.0.4/32",
		},
		{
			name:   "skips network and broadcast on /24",
			subnet: "10.10.0.0/24",
			want:   "10.10.0.1/32", // .0 (network) skipped
		},
		{
			name:    "exhausted /30",
			subnet:  "10.0.0.0/30", // usable .1 .2
			used:    []string{"10.0.0.1/32", "10.0.0.2/32"},
			wantErr: true,
		},
		{
			name:   "/31 point-to-point uses both",
			subnet: "10.0.0.0/31",
			used:   []string{"10.0.0.0/32"},
			want:   "10.0.0.1/32",
		},
		{
			name:   "fills a hole",
			subnet: "10.10.0.0/24",
			used:   []string{"10.10.0.1/32", "10.10.0.3/32"},
			want:   "10.10.0.2/32",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Conf{}
			for _, u := range tt.used {
				c.AddPeer(Peer{AllowedIPs: []netip.Prefix{netip.MustParsePrefix(u)}})
			}
			var reserved []netip.Addr
			for _, r := range tt.reserved {
				reserved = append(reserved, netip.MustParseAddr(r))
			}
			got, err := c.AllocateIP(netip.MustParsePrefix(tt.subnet), reserved)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != netip.MustParsePrefix(tt.want) {
				t.Errorf("AllocateIP = %v, want %v", got, tt.want)
			}
		})
	}
}
