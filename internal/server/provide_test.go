package server

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgconf"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// provideDirs returns a fresh (wgDir, sidecarDir) pair under t.TempDir and points
// config.ServerDir at the sidecar dir so a round-trip through LoadServer works.
func provideDirs(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	wgDir := filepath.Join(root, "wireguard")
	sidecarDir := filepath.Join(root, "wgpeer")
	t.Setenv("WGPEER_CONFIG_DIR", sidecarDir)
	return wgDir, sidecarDir
}

func TestProvide_writesConfAndSidecar(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	resp := Provide(ProvideOptions{
		Iface:      "wg7",
		Subnet:     netip.MustParsePrefix("172.19.0.0/16"),
		Endpoint:   "vpn.example.com",
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
		Up:         false,
	})
	if !resp.OK {
		t.Fatalf("provide failed: %s", resp.Message)
	}

	// Reported fields.
	if resp.Address != "172.19.0.1/16" {
		t.Errorf("address = %q, want 172.19.0.1/16", resp.Address)
	}
	if resp.Subnet != "172.19.0.0/16" {
		t.Errorf("subnet = %q, want 172.19.0.0/16", resp.Subnet)
	}
	if resp.ListenPort < minAutoPort || resp.ListenPort >= maxAutoPort {
		t.Errorf("listen port %d outside [%d,%d)", resp.ListenPort, minAutoPort, maxAutoPort)
	}
	if resp.Enabled {
		t.Errorf("Enabled should be false with Up=false")
	}
	if len(resp.Endpoints) != 1 || resp.Endpoints[0].Name != "public" {
		t.Fatalf("endpoints = %+v, want one named public", resp.Endpoints)
	}
	wantAddr := "vpn.example.com:" + strconv.Itoa(resp.ListenPort)
	if resp.Endpoints[0].Addr != wantAddr {
		t.Errorf("endpoint addr = %q, want %q", resp.Endpoints[0].Addr, wantAddr)
	}

	// Conf file: 0600, valid [Interface], derived pubkey matches the response.
	confPath := filepath.Join(wgDir, "wg7.conf")
	fi, err := os.Stat(confPath)
	if err != nil {
		t.Fatalf("stat conf: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("conf perm = %o, want 600", fi.Mode().Perm())
	}
	confData, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}
	conf, err := wgconf.Parse(confData)
	if err != nil {
		t.Fatalf("generated conf does not parse: %v", err)
	}
	if len(conf.Peers) != 0 {
		t.Errorf("fresh conf should have no peers, got %d", len(conf.Peers))
	}
	if !strings.Contains(string(confData), "Address = 172.19.0.1/16") {
		t.Errorf("conf missing Address line:\n%s", confData)
	}
	if !strings.Contains(string(confData), "ListenPort = "+strconv.Itoa(resp.ListenPort)) {
		t.Errorf("conf missing ListenPort line:\n%s", confData)
	}
	gotPub, err := wgkey.PublicFromPrivateBase64(conf.InterfacePrivateKey())
	if err != nil {
		t.Fatalf("deriving pub from conf: %v", err)
	}
	if gotPub != resp.ServerPublicKey {
		t.Errorf("conf private key derives %q, response says %q", gotPub, resp.ServerPublicKey)
	}

	// Sidecar: 0644 and round-trips through the real loader.
	sidecarPath := filepath.Join(sidecarDir, "wg7.toml")
	sfi, err := os.Stat(sidecarPath)
	if err != nil {
		t.Fatalf("stat sidecar: %v", err)
	}
	if sfi.Mode().Perm() != 0o644 {
		t.Errorf("sidecar perm = %o, want 644", sfi.Mode().Perm())
	}
	cfg, err := config.LoadServer("wg7")
	if err != nil {
		t.Fatalf("generated sidecar does not load: %v", err)
	}
	if cfg.Subnet != "172.19.0.0/16" {
		t.Errorf("sidecar subnet = %q", cfg.Subnet)
	}
	if cfg.ConfPath != confPath {
		t.Errorf("sidecar conf_path = %q, want %q", cfg.ConfPath, confPath)
	}
	if len(cfg.Reserved) != 1 || cfg.Reserved[0] != "172.19.0.1" {
		t.Errorf("sidecar reserved = %v, want [172.19.0.1]", cfg.Reserved)
	}
	if cfg.Template.PersistentKeepalive != 25 || !cfg.Template.PSKDefault {
		t.Errorf("sidecar template defaults wrong: %+v", cfg.Template)
	}
	// DNS and MTU default to unset (the client omits the lines); AllowedIPs
	// defaults to full-tunnel.
	if cfg.Template.MTU != 0 {
		t.Errorf("mtu should be unset by default, got %d", cfg.Template.MTU)
	}
	if len(cfg.Template.DNS) != 0 {
		t.Errorf("dns should be unset by default, got %v", cfg.Template.DNS)
	}
	if !slices.Equal(cfg.Template.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("allowed_ips = %v, want full-tunnel", cfg.Template.AllowedIPs)
	}
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0].Name != "public" || cfg.Endpoints[0].Addr != wantAddr {
		t.Errorf("sidecar endpoints = %+v", cfg.Endpoints)
	}
}

func TestProvide_customTemplate(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	resp := Provide(ProvideOptions{
		Iface:      "wg0",
		Subnet:     netip.MustParsePrefix("172.19.0.0/16"),
		Endpoint:   "h",
		AllowedIPs: []string{"172.19.0.0/16"},
		DNS:        []string{"1.1.1.1", "1.0.0.1"},
		MTU:        1420,
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
	})
	if !resp.OK {
		t.Fatalf("provide failed: %s", resp.Message)
	}
	if !slices.Equal(resp.AllowedIPs, []string{"172.19.0.0/16"}) || !slices.Equal(resp.DNS, []string{"1.1.1.1", "1.0.0.1"}) || resp.MTU != 1420 {
		t.Errorf("response template fields wrong: allowed=%v dns=%v mtu=%d", resp.AllowedIPs, resp.DNS, resp.MTU)
	}
	cfg, err := config.LoadServer("wg0")
	if err != nil {
		t.Fatalf("load sidecar: %v", err)
	}
	if !slices.Equal(cfg.Template.AllowedIPs, []string{"172.19.0.0/16"}) {
		t.Errorf("sidecar allowed_ips = %v", cfg.Template.AllowedIPs)
	}
	if !slices.Equal(cfg.Template.DNS, []string{"1.1.1.1", "1.0.0.1"}) {
		t.Errorf("sidecar dns = %v", cfg.Template.DNS)
	}
	if cfg.Template.MTU != 1420 {
		t.Errorf("sidecar mtu = %d, want 1420", cfg.Template.MTU)
	}
}

func TestResolveAllowedIPs(t *testing.T) {
	subnet := netip.MustParsePrefix("172.19.0.0/16")
	cases := []struct {
		in   string
		want []string
		err  bool
	}{
		{"0.0.0.0/0,::/0", []string{"0.0.0.0/0", "::/0"}, false}, // full-tunnel default
		{"subnet", []string{"172.19.0.0/16"}, false},            // shortcut
		{"10.0.0.0/8, 192.168.0.0/16", []string{"10.0.0.0/8", "192.168.0.0/16"}, false},
		{"nonsense", nil, true},
		{"10.0.0.1", nil, true}, // bare IP, not a prefix
		{"", nil, true},         // empty
		{" , ", nil, true},      // all-empty
	}
	for _, tc := range cases {
		got, err := ResolveAllowedIPs(tc.in, subnet)
		if tc.err {
			if err == nil {
				t.Errorf("ResolveAllowedIPs(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveAllowedIPs(%q) error: %v", tc.in, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("ResolveAllowedIPs(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestProvide_explicitAddressAndPort(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	resp := Provide(ProvideOptions{
		Iface:      "wg0",
		Subnet:     netip.MustParsePrefix("10.8.0.0/24"),
		Address:    netip.MustParseAddr("10.8.0.254"),
		ListenPort: 51820,
		Endpoint:   "1.2.3.4:443", // host:port passes through verbatim
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
	})
	if !resp.OK {
		t.Fatalf("provide failed: %s", resp.Message)
	}
	if resp.Address != "10.8.0.254/24" {
		t.Errorf("address = %q, want 10.8.0.254/24", resp.Address)
	}
	if resp.ListenPort != 51820 {
		t.Errorf("listen port = %d, want 51820", resp.ListenPort)
	}
	if resp.Endpoints[0].Addr != "1.2.3.4:443" {
		t.Errorf("endpoint addr = %q, want 1.2.3.4:443 (verbatim)", resp.Endpoints[0].Addr)
	}
}

func TestProvide_autodetectEndpoints(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	defer stub(&detectGlobalV4, func() ([]namedAddr, error) {
		return []namedAddr{
			{Iface: "eth0", IP: netip.MustParseAddr("185.18.221.124")},
			{Iface: "eth1", IP: netip.MustParseAddr("203.0.113.9")},
		}, nil
	})()

	resp := Provide(ProvideOptions{
		Iface:      "wg0",
		Subnet:     netip.MustParsePrefix("172.19.0.0/16"),
		ListenPort: 40000,
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
	})
	if !resp.OK {
		t.Fatalf("provide failed: %s", resp.Message)
	}
	if len(resp.Endpoints) != 2 {
		t.Fatalf("want 2 endpoints, got %+v", resp.Endpoints)
	}
	if resp.Endpoints[0].Name != "eth0" || resp.Endpoints[0].Addr != "185.18.221.124:40000" {
		t.Errorf("endpoint[0] = %+v", resp.Endpoints[0])
	}
	if resp.Endpoints[1].Name != "eth1" || resp.Endpoints[1].Addr != "203.0.113.9:40000" {
		t.Errorf("endpoint[1] = %+v", resp.Endpoints[1])
	}
}

func TestProvide_noPublicIPFails(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	defer stub(&detectGlobalV4, func() ([]namedAddr, error) { return nil, nil })()

	resp := Provide(ProvideOptions{
		Iface:      "wg0",
		Subnet:     netip.MustParsePrefix("172.19.0.0/16"),
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
	})
	if resp.OK {
		t.Fatal("expected failure when no public IPv4 and no --endpoint")
	}
	if resp.Error != protocol.ErrBadRequest {
		t.Errorf("error = %q, want bad_request", resp.Error)
	}
	// Nothing should have been written.
	if _, err := os.Stat(filepath.Join(wgDir, "wg0.conf")); !os.IsNotExist(err) {
		t.Errorf("conf should not exist after a pre-write failure")
	}
}

func TestProvide_refusesExisting(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	if err := os.MkdirAll(wgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(wgDir, "wg0.conf")
	if err := os.WriteFile(confPath, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := Provide(ProvideOptions{
		Iface:      "wg0",
		Subnet:     netip.MustParsePrefix("10.0.0.0/24"),
		Endpoint:   "x",
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
	})
	if resp.OK {
		t.Fatal("expected refusal when conf already exists")
	}
	if !strings.Contains(resp.Message, "already exists") {
		t.Errorf("message = %q, want 'already exists'", resp.Message)
	}
}

func TestProvide_enableCalledAndFailureReported(t *testing.T) {
	// Success path: runEnable is invoked with the iface and Enabled is set.
	wgDir, sidecarDir := provideDirs(t)
	var gotIface string
	defer stub(&runEnable, func(iface string) error { gotIface = iface; return nil })()
	resp := Provide(ProvideOptions{
		Iface:      "wg9",
		Subnet:     netip.MustParsePrefix("10.0.0.0/24"),
		Endpoint:   "h",
		WGDir:      wgDir,
		SidecarDir: sidecarDir,
		Up:         true,
	})
	if !resp.OK || !resp.Enabled {
		t.Fatalf("want OK+Enabled, got ok=%v enabled=%v msg=%s", resp.OK, resp.Enabled, resp.Message)
	}
	if gotIface != "wg9" {
		t.Errorf("runEnable got iface %q, want wg9", gotIface)
	}

	// Failure path: files are still written, but OK=false with the reason.
	wgDir2, sidecarDir2 := provideDirs(t)
	defer stub(&runEnable, func(iface string) error { return errBoom })()
	resp2 := Provide(ProvideOptions{
		Iface:      "wg9",
		Subnet:     netip.MustParsePrefix("10.0.0.0/24"),
		Endpoint:   "h",
		WGDir:      wgDir2,
		SidecarDir: sidecarDir2,
		Up:         true,
	})
	if resp2.OK {
		t.Fatal("expected OK=false when bring-up fails")
	}
	if !strings.Contains(resp2.Message, "config written but bring-up failed") {
		t.Errorf("message = %q", resp2.Message)
	}
	if _, err := os.Stat(filepath.Join(wgDir2, "wg9.conf")); err != nil {
		t.Errorf("conf should still be written on bring-up failure: %v", err)
	}
}

func TestProvide_badInput(t *testing.T) {
	wgDir, sidecarDir := provideDirs(t)
	base := ProvideOptions{Endpoint: "h", WGDir: wgDir, SidecarDir: sidecarDir}
	cases := []struct {
		name string
		mut  func(*ProvideOptions)
	}{
		{"empty iface", func(o *ProvideOptions) { o.Iface = ""; o.Subnet = netip.MustParsePrefix("10.0.0.0/24") }},
		{"bad iface char", func(o *ProvideOptions) { o.Iface = "wg 0"; o.Subnet = netip.MustParsePrefix("10.0.0.0/24") }},
		{"no subnet", func(o *ProvideOptions) { o.Iface = "wg0" }},
		{"subnet too small", func(o *ProvideOptions) { o.Iface = "wg0"; o.Subnet = netip.MustParsePrefix("10.0.0.0/31") }},
		{"address outside subnet", func(o *ProvideOptions) {
			o.Iface = "wg0"
			o.Subnet = netip.MustParsePrefix("10.0.0.0/24")
			o.Address = netip.MustParseAddr("10.9.9.9")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mut(&o)
			resp := Provide(o)
			if resp.OK {
				t.Fatalf("%s: expected failure", tc.name)
			}
			if resp.Error != protocol.ErrBadRequest {
				t.Errorf("%s: error = %q, want bad_request", tc.name, resp.Error)
			}
		})
	}
}

func TestIsPublicV4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"185.18.221.124", true},
		{"203.0.113.9", true},
		{"10.0.0.1", false},        // RFC1918
		{"172.21.0.1", false},      // RFC1918
		{"192.168.231.7", false},   // RFC1918
		{"127.0.0.1", false},       // loopback
		{"169.254.1.1", false},     // link-local
		{"0.0.0.0", false},         // unspecified
		{"2a13:2c0::475c", false},  // IPv6 (v1 is v4-only here)
	}
	for _, tc := range cases {
		if got := isPublicV4(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isPublicV4(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestValidIface(t *testing.T) {
	good := []string{"wg0", "wg-quick0", "wg_1", "a.b", "WG123456789012"}
	for _, n := range good {
		if err := validIface(n); err != nil {
			t.Errorf("validIface(%q) = %v, want nil", n, err)
		}
	}
	bad := []string{"", "wg 0", "wg/0", "toolonginterface", "wg\n0"}
	for _, n := range bad {
		if err := validIface(n); err == nil {
			t.Errorf("validIface(%q) = nil, want error", n)
		}
	}
}

// --- helpers ---------------------------------------------------------------

var errBoom = &boomError{}

type boomError struct{}

func (*boomError) Error() string { return "boom" }

// stub swaps *p to v and returns a restore func for defer.
func stub[T any](p *T, v T) func() {
	old := *p
	*p = v
	return func() { *p = old }
}
