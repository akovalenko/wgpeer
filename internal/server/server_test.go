package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgconf"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// newTestServer builds a Server over a temp conf with a real [Interface] key
// and a no-op Apply (no live wg device in unit tests).
func newTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")

	priv, err := wgkey.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := wgkey.PublicFromPrivateBase64(wgkey.Encode(priv))
	if err != nil {
		t.Fatal(err)
	}
	initial := "[Interface]\nPrivateKey = " + wgkey.Encode(priv) + "\nListenPort = 51820\n"
	if err := os.WriteFile(confPath, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Cfg: &config.ServerConfig{
			Iface:    "wg0",
			ConfPath: confPath,
			Subnet:   "10.10.0.0/24",
			Reserved: []string{"10.10.0.1"},
			Template: config.Template{
				DNS:                 []string{"10.10.0.1"},
				AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
				PersistentKeepalive: 25,
				MTU:                 1340,
				PSKDefault:          true,
			},
			Endpoints: []protocol.Endpoint{{Name: "public", Addr: "vpn.example:51820"}},
		},
		Apply: func(string, string) error { return nil },
	}
	return s, confPath, serverPub
}

// clientPub returns a fresh valid public key string for use as a peer key.
func clientPub(t *testing.T) string {
	t.Helper()
	priv, err := wgkey.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := wgkey.PublicFromPrivateBase64(wgkey.Encode(priv))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestServerAddListKill(t *testing.T) {
	s, confPath, serverPub := newTestServer(t)

	// First add: lowest free host after the reserved .1 is .2.
	resp := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "alice", PublicKey: clientPub(t)})
	if !resp.OK {
		t.Fatalf("add alice: %+v", resp.Status)
	}
	if resp.IP != "10.10.0.2/32" {
		t.Errorf("alice ip = %q, want 10.10.0.2/32", resp.IP)
	}
	if resp.ServerPublicKey != serverPub {
		t.Errorf("server pub = %q, want %q", resp.ServerPublicKey, serverPub)
	}
	if resp.MTU != 1340 || resp.PersistentKeepalive != 25 || resp.Subnet != "10.10.0.0/24" {
		t.Errorf("template fields wrong: %+v", resp)
	}

	// Duplicate name → name_taken.
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "alice", PublicKey: clientPub(t)}); r.Error != protocol.ErrNameTaken {
		t.Errorf("duplicate add error = %q, want name_taken", r.Error)
	}

	// Missing fields → bad_request.
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "x"}); r.Error != protocol.ErrBadRequest {
		t.Errorf("empty pubkey error = %q, want bad_request", r.Error)
	}

	// Second add gets the next free IP.
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "bob", PublicKey: clientPub(t)}); r.IP != "10.10.0.3/32" {
		t.Errorf("bob ip = %q, want 10.10.0.3/32", r.IP)
	}

	// List shows both.
	lr := s.List()
	if !lr.OK || len(lr.Peers) != 2 {
		t.Fatalf("list = %+v", lr)
	}

	// Kill alice.
	kr := s.Kill(protocol.Request{Op: protocol.OpKill, Name: "alice"})
	if !kr.OK || kr.Removed == nil || kr.Removed.Name != "alice" {
		t.Fatalf("kill alice = %+v", kr)
	}
	if r := s.Kill(protocol.Request{Op: protocol.OpKill, Name: "ghost"}); r.Error != protocol.ErrNotFound {
		t.Errorf("kill ghost error = %q, want not_found", r.Error)
	}

	// On-disk file reflects the result and still round-trips.
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := wgconf.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Peers) != 1 || conf.Peers[0].Name != "bob" {
		t.Errorf("file peers = %+v", conf.Peers)
	}
	// [Interface] header preserved verbatim.
	if conf.InterfacePrivateKey() == "" {
		t.Errorf("interface PrivateKey lost from header")
	}
}

func TestServerNoFreeIP(t *testing.T) {
	s, _, _ := newTestServer(t)
	s.Cfg.Subnet = "10.20.0.0/30" // usable .1 .2
	s.Cfg.Reserved = nil
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "a", PublicKey: clientPub(t)}); !r.OK {
		t.Fatalf("add a: %+v", r.Status)
	}
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "b", PublicKey: clientPub(t)}); !r.OK {
		t.Fatalf("add b: %+v", r.Status)
	}
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "c", PublicKey: clientPub(t)}); r.Error != protocol.ErrNoFreeIP {
		t.Errorf("third add error = %q, want no_free_ip", r.Error)
	}
}
