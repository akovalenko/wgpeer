//go:build integration && linux

// Integration test for the server's real apply path (spec §13, Stage 2). It
// stands up a disposable WireGuard interface, runs add/kill through the real
// `wg syncconf`, and checks the live device via `wg show`.
//
//	sudo go test -tags integration ./internal/server/
//
// Skips unless run as root with the wireguard kernel module available.
package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

const testIface = "wgpeertest0"

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
}

func TestIntegrationApply(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("integration test needs root")
	}
	if err := exec.Command("ip", "link", "add", testIface, "type", "wireguard").Run(); err != nil {
		t.Skipf("cannot create wireguard interface (module missing?): %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", testIface).Run() })

	dir := t.TempDir()
	confPath := filepath.Join(dir, testIface+".conf")
	priv, err := wgkey.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	conf := "[Interface]\nPrivateKey = " + wgkey.Encode(priv) + "\nListenPort = 51999\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatal(err)
	}

	s := New(&config.ServerConfig{
		Iface:     testIface,
		ConfPath:  confPath,
		Subnet:    "10.30.0.0/24",
		Reserved:  []string{"10.30.0.1"},
		Endpoints: []protocol.Endpoint{{Name: "test", Addr: "127.0.0.1:51999"}},
	})

	clientPriv, _ := wgkey.GeneratePrivateKey()
	clientPub, _ := wgkey.PublicFromPrivateBase64(wgkey.Encode(clientPriv))

	resp := s.Add(protocol.Request{Op: protocol.OpAdd, Name: "intgr", PublicKey: clientPub})
	if !resp.OK {
		t.Fatalf("add: %+v", resp.Status)
	}

	show, err := exec.Command("wg", "show", testIface, "peers").CombinedOutput()
	if err != nil {
		t.Fatalf("wg show: %v: %s", err, show)
	}
	if !strings.Contains(string(show), clientPub) {
		t.Fatalf("peer %s not present on live device:\n%s", clientPub, show)
	}

	kr := s.Kill(protocol.Request{Op: protocol.OpKill, Name: "intgr"})
	if !kr.OK {
		t.Fatalf("kill: %+v", kr.Status)
	}
	show, _ = exec.Command("wg", "show", testIface, "peers").CombinedOutput()
	if strings.Contains(string(show), clientPub) {
		t.Fatalf("peer %s still present after kill:\n%s", clientPub, show)
	}
}
