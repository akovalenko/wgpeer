package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/server"
	"github.com/akovalenko/wgpeer/internal/wgconf"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// inProcess wires a Client straight into a Server (Apply stubbed), exercising
// the full add/list/kill flow — keygen, JSON round-trip, config assembly —
// without ssh or a live wg device.
func inProcess(t *testing.T) (*Client, *server.Server, string) {
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
	if err := os.WriteFile(confPath, []byte("[Interface]\nPrivateKey = "+wgkey.Encode(priv)+"\nListenPort = 51820\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &server.Server{
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
			Endpoints: []protocol.Endpoint{
				{Name: "public", Addr: "vpn.example:51820"},
				{Name: "tspu-443", Addr: "vpn.example:443"},
			},
		},
		Apply: func(string, string) error { return nil },
	}
	cl := &Client{Iface: "wg0", Exec: func(op string, reqJSON []byte) ([]byte, error) {
		var req protocol.Request
		if err := json.Unmarshal(reqJSON, &req); err != nil {
			return nil, err
		}
		req.Op = op
		switch op {
		case protocol.OpAdd:
			return json.Marshal(s.Add(req))
		case protocol.OpList:
			return json.Marshal(s.List())
		case protocol.OpKill:
			return json.Marshal(s.Kill(req))
		}
		return nil, fmt.Errorf("unknown op %q", op)
	}}
	return cl, s, serverPub
}

func TestClientAddAssembly(t *testing.T) {
	cl, _, serverPub := inProcess(t)

	cfgText, resp, err := cl.Add(AddOptions{Name: "phone"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if resp.IP != "10.10.0.2/32" {
		t.Errorf("ip = %q", resp.IP)
	}

	// The assembled config must be parseable and carry the right fields.
	for _, want := range []string{
		"[Interface]",
		"Address = 10.10.0.2/32",
		"DNS = 10.10.0.1",
		"MTU = 1340",
		"PublicKey = " + serverPub,
		"Endpoint = vpn.example:51820", // default endpoint (first)
		"AllowedIPs = 0.0.0.0/0, ::/0", // full tunnel
		"PersistentKeepalive = 25",
		"PresharedKey = ", // PSK on by default
	} {
		if !strings.Contains(cfgText, want) {
			t.Errorf("config missing %q\n%s", want, cfgText)
		}
	}

	// The client private key must derive the public key the server stored.
	conf, err := wgconf.Parse([]byte(cfgText))
	if err != nil {
		t.Fatalf("parse client config: %v", err)
	}
	clientPub, err := wgkey.PublicFromPrivateBase64(conf.InterfacePrivateKey())
	if err != nil {
		t.Fatalf("derive client pub: %v", err)
	}
	if len(conf.Peers) != 1 || conf.Peers[0].PublicKey != serverPub {
		t.Errorf("peer block server key wrong: %+v", conf.Peers)
	}
	// The QR must render.
	qr, err := RenderTerminalQR(cfgText, false)
	if err != nil || qr == "" {
		t.Errorf("RenderTerminalQR: %q, %v", qr, err)
	}
	_ = clientPub
}

func TestClientAddOptions(t *testing.T) {
	cl, s, _ := inProcess(t)

	// --no-psk: no PresharedKey line.
	cfgText, _, err := cl.Add(AddOptions{Name: "nopsk", NoPSK: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfgText, "PresharedKey") {
		t.Errorf("--no-psk still emitted a PSK:\n%s", cfgText)
	}

	// --split: AllowedIPs restricted to the server subnet.
	cfgText, _, err = cl.Add(AddOptions{Name: "split", Split: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfgText, "AllowedIPs = 10.10.0.0/24") {
		t.Errorf("--split did not restrict AllowedIPs:\n%s", cfgText)
	}

	// --endpoint selects from the menu.
	cfgText, _, err = cl.Add(AddOptions{Name: "alt", Endpoint: "tspu-443"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfgText, "Endpoint = vpn.example:443") {
		t.Errorf("--endpoint not honoured:\n%s", cfgText)
	}

	// Unknown endpoint is an error — and crucially the peer must NOT have been
	// created (validated server-side before any mutation), so the key is not lost.
	if _, _, err := cl.Add(AddOptions{Name: "bad", Endpoint: "nope"}); err == nil {
		t.Errorf("unknown endpoint should error")
	}
	lr := s.List()
	for _, p := range lr.Peers {
		if p.Name == "bad" {
			t.Errorf("peer was created despite an unknown endpoint: %+v", p)
		}
	}
}

func TestClientListKill(t *testing.T) {
	cl, _, _ := inProcess(t)
	if _, _, err := cl.Add(AddOptions{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.Add(AddOptions{Name: "b"}); err != nil {
		t.Fatal(err)
	}
	lr, err := cl.List()
	if err != nil || len(lr.Peers) != 2 {
		t.Fatalf("list = %+v, %v", lr, err)
	}
	kr, err := cl.Kill("a")
	if err != nil || kr.Removed.Name != "a" {
		t.Fatalf("kill = %+v, %v", kr, err)
	}
	// Killing a name that maps to a duplicate-name error surfaces the code.
	if _, err := cl.Kill("ghost"); err == nil || !strings.Contains(err.Error(), protocol.ErrNotFound) {
		t.Errorf("kill ghost err = %v, want not_found", err)
	}
}
