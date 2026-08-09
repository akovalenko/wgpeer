//go:build linux

package server

import (
	"errors"
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

func TestServerRename(t *testing.T) {
	s, confPath, _ := newTestServer(t)
	aliceKey, bobKey := clientPub(t), clientPub(t)
	addA := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "alice", PublicKey: aliceKey})
	if !addA.OK {
		t.Fatalf("add alice: %+v", addA.Status)
	}
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "bob", PublicKey: bobKey}); !r.OK {
		t.Fatalf("add bob: %+v", r.Status)
	}

	// Happy path: the label moves, the identity does not.
	r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "alice", NewName: "алиса"})
	if !r.OK || r.Renamed == nil {
		t.Fatalf("rename alice: %+v", r)
	}
	if r.Renamed.From != "alice" || r.Renamed.To != "алиса" || r.Renamed.PublicKey != aliceKey {
		t.Errorf("renamed = %+v, want alice→алиса with the original key", r.Renamed)
	}

	// The peer keeps its key and address; the old name is gone.
	lr := s.List()
	var found bool
	for _, p := range lr.Peers {
		if p.Name == "alice" {
			t.Errorf("old name still present: %+v", p)
		}
		if p.Name == "алиса" {
			found = true
			if p.PublicKey != aliceKey || p.IP != addA.IP {
				t.Errorf("rename changed identity/address: %+v, want key %s ip %s", p, aliceKey, addA.IP)
			}
		}
	}
	if !found {
		t.Errorf("renamed peer missing from list: %+v", lr.Peers)
	}

	// Renaming to itself is a no-op that succeeds (the duplicate check must not
	// trip on the peer being renamed).
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "алиса", NewName: "алиса"}); !r.OK {
		t.Errorf("self-rename should succeed: %+v", r.Status)
	}

	// Duplicate target → name_taken (the label is what kill/rename resolve on).
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "алиса", NewName: "bob"}); r.Error != protocol.ErrNameTaken {
		t.Errorf("rename onto an existing name = %q, want name_taken", r.Error)
	}

	// Unknown source → not_found.
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "ghost", NewName: "x"}); r.Error != protocol.ErrNotFound {
		t.Errorf("rename ghost = %q, want not_found", r.Error)
	}

	// Missing/invalid names → bad_request.
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, NewName: "x"}); r.Error != protocol.ErrBadRequest {
		t.Errorf("rename with no source = %q, want bad_request", r.Error)
	}
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "bob", NewName: ""}); r.Error != protocol.ErrBadRequest {
		t.Errorf("rename to an empty name = %q, want bad_request", r.Error)
	}

	// The file must still parse, with both peers intact under the right labels.
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := wgconf.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Peers) != 2 {
		t.Fatalf("file peers = %+v", conf.Peers)
	}
	if conf.FindByName("алиса") < 0 || conf.FindByName("bob") < 0 {
		t.Errorf("file names wrong: %+v", conf.Peers)
	}
	if conf.InterfacePrivateKey() == "" {
		t.Errorf("interface PrivateKey lost from header")
	}
}

// TestServerRenameRejectsInjection: a rejected rename must leave the conf byte
// for byte as it was — a newline in the target would otherwise forge [Peer]
// blocks through the "# name:" comment.
func TestServerRenameRejectsInjection(t *testing.T) {
	s, confPath, _ := newTestServer(t)
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "alice", PublicKey: clientPub(t)}); !r.OK {
		t.Fatalf("add alice: %+v", r.Status)
	}
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	evil := "evil\n[Peer]\nPublicKey = " + clientPub(t) + "\nAllowedIPs = 0.0.0.0/0"
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "alice", NewName: evil}); r.Error != protocol.ErrBadRequest {
		t.Fatalf("injection rename = %q, want bad_request", r.Error)
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("conf must be untouched after a rejected rename")
	}
}

// TestServerRenameSkipsApply pins the deliberate asymmetry with add/kill: a name
// lives in a comment, so there is nothing for `wg syncconf` to push and a
// down-but-configured interface must not make rename fail.
func TestServerRenameSkipsApply(t *testing.T) {
	s, _, _ := newTestServer(t)
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "alice", PublicKey: clientPub(t)}); !r.OK {
		t.Fatalf("add alice: %+v", r.Status)
	}
	applied := 0
	s.Apply = func(string, string) error {
		applied++
		return errors.New("wg syncconf: interface is down")
	}
	if r := s.Rename(protocol.Request{Op: protocol.OpRename, Name: "alice", NewName: "bob"}); !r.OK {
		t.Errorf("rename should not depend on the live device: %+v", r.Status)
	}
	if applied != 0 {
		t.Errorf("rename called Apply %d times, want 0", applied)
	}
}

func TestServerRejectsNameInjection(t *testing.T) {
	s, confPath, _ := newTestServer(t)
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	evil := "evil\n[Peer]\nPublicKey = " + clientPub(t) + "\nAllowedIPs = 0.0.0.0/0"
	r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: evil, PublicKey: clientPub(t)})
	if r.Error != protocol.ErrBadRequest {
		t.Fatalf("injection add error = %q, want bad_request", r.Error)
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("conf must be untouched after a rejected add")
	}
}

func TestServerRejectsUnknownEndpoint(t *testing.T) {
	s, confPath, _ := newTestServer(t)
	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "x", PublicKey: clientPub(t), Endpoint: "nope"})
	if r.Error != protocol.ErrBadRequest {
		t.Fatalf("unknown endpoint error = %q, want bad_request", r.Error)
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("conf must be untouched after a rejected endpoint (no orphaned peer)")
	}
	// A valid endpoint name (and the default empty) still works.
	if r := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "y", PublicKey: clientPub(t), Endpoint: "public"}); !r.OK {
		t.Fatalf("valid endpoint add: %+v", r.Status)
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
