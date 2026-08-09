package client

import (
	"slices"
	"testing"
)

func TestSSHArgv(t *testing.T) {
	cases := []struct {
		name string
		cfg  SSHConfig
		want []string
	}{
		{
			name: "defaults: plain ssh + wgpeer on PATH",
			cfg:  SSHConfig{Target: "vm1536"},
			want: []string{"ssh", "vm1536", "wgpeer", "server", "--iface", "wg0", "list"},
		},
		{
			name: "sudo prefixes the remote command",
			cfg:  SSHConfig{Target: "vm1536", Sudo: true},
			want: []string{"ssh", "vm1536", "sudo", "wgpeer", "server", "--iface", "wg0", "list"},
		},
		{
			name: "ssh_command override (e.g. -F)",
			cfg:  SSHConfig{Command: []string{"ssh", "-F", "/p/cfg"}, Target: "vm1536"},
			want: []string{"ssh", "-F", "/p/cfg", "vm1536", "wgpeer", "server", "--iface", "wg0", "list"},
		},
		{
			name: "wgpeer_path override + sudo",
			cfg:  SSHConfig{Target: "vm1536", Sudo: true, WgpeerPath: "/usr/local/bin/wgpeer"},
			want: []string{"ssh", "vm1536", "sudo", "/usr/local/bin/wgpeer", "server", "--iface", "wg0", "list"},
		},
		{
			name: "both overrides together",
			cfg:  SSHConfig{Command: []string{"ssh", "-F", "/p/cfg"}, Target: "alias", WgpeerPath: "/opt/wgpeer"},
			want: []string{"ssh", "-F", "/p/cfg", "alias", "/opt/wgpeer", "server", "--iface", "wg0", "list"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewSSH(tc.cfg, "wg0")
			if got := c.sshArgv("list"); !slices.Equal(got, tc.want) {
				t.Errorf("sshArgv = %v, want %v", got, tc.want)
			}
			// The override must not be mutated by argv construction (append aliasing).
			if tc.cfg.Command != nil && !slices.Equal(c.SSHCommand, tc.cfg.Command) {
				t.Errorf("SSHCommand mutated: %v != %v", c.SSHCommand, tc.cfg.Command)
			}
		})
	}
}
