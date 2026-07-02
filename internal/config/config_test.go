package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestLoadClient_sshOverrides loads a client menu with the optional ssh_command
// and wgpeer_path overrides through the real path (os.UserConfigDir honours
// XDG_CONFIG_HOME), locking the TOML tags and confirming unset entries stay bare.
func TestLoadClient_sshOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "wgpeer")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	menu := `
default_server = "vm"

[[server]]
name        = "vm"
ssh         = "vm1536"
ssh_command = ["ssh", "-F", "/etc/wgpeer/ssh_config"]
sudo        = true
wgpeer_path = "/usr/local/bin/wgpeer"
ifaces      = ["wg0", "wg1"]

[[server]]
name   = "plain"
ssh    = "user@host"
ifaces = ["wg0"]
`
	if err := os.WriteFile(filepath.Join(cfgDir, "client.toml"), []byte(menu), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient()
	if err != nil {
		t.Fatalf("LoadClient: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("want 2 servers, got %d", len(cfg.Servers))
	}

	vm := cfg.Servers[0]
	if !slices.Equal(vm.SSHCommand, []string{"ssh", "-F", "/etc/wgpeer/ssh_config"}) {
		t.Errorf("ssh_command = %v", vm.SSHCommand)
	}
	if vm.WgpeerPath != "/usr/local/bin/wgpeer" {
		t.Errorf("wgpeer_path = %q, want /usr/local/bin/wgpeer", vm.WgpeerPath)
	}
	if !vm.Sudo {
		t.Errorf("sudo = false, want true")
	}

	// An entry without the overrides parses with zero values; the client layer
	// supplies the ["ssh"] / "wgpeer" defaults, not the loader.
	plain := cfg.Servers[1]
	if len(plain.SSHCommand) != 0 {
		t.Errorf("plain ssh_command = %v, want empty", plain.SSHCommand)
	}
	if plain.WgpeerPath != "" {
		t.Errorf("plain wgpeer_path = %q, want empty", plain.WgpeerPath)
	}
}
