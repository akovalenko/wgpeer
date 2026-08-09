//go:build linux && !clientonly

package cli

import (
	"strings"
	"testing"

	"github.com/akovalenko/wgpeer/internal/server"
)

func TestConfirmRemove(t *testing.T) {
	plan := server.RemovePlan{
		Iface:         "wg0",
		ConfPath:      "/etc/wireguard/wg0.conf",
		SidecarPath:   "/etc/wgpeer/wg0.toml",
		BackupPath:    "/etc/wireguard/wg0.conf.bak-20260702",
		ConfExists:    true,
		SidecarExists: true,
	}
	tests := []struct {
		answer string
		want   bool
	}{
		{"y\n", true},
		{"Y\n", true},
		{"yes\n", true},
		{"  yes  \n", true},
		{"n\n", false},
		{"no\n", false},
		{"\n", false}, // bare enter = the safe default (cancel)
		{"", false},   // EOF (no terminal input) cancels
		{"yeah\n", false},
		{"ok\n", false},
	}
	for _, tt := range tests {
		t.Run(strings.TrimSpace(tt.answer), func(t *testing.T) {
			var out strings.Builder
			got := confirmRemove(strings.NewReader(tt.answer), &out, plan)
			if got != tt.want {
				t.Errorf("confirmRemove(%q) = %v, want %v", tt.answer, got, tt.want)
			}
			// The summary must name the interface and the destructive actions
			// regardless of the answer, so the user always sees what is at stake.
			for _, want := range []string{"wg0", "stop & disable", plan.SidecarPath, plan.ConfPath, plan.BackupPath} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("summary missing %q:\n%s", want, out.String())
				}
			}
		})
	}
}

// TestConfirmRemove_noBackupWarning checks the summary flags an unrecoverable
// removal when no backup will be taken.
func TestConfirmRemove_noBackupWarning(t *testing.T) {
	plan := server.RemovePlan{
		Iface:       "wg0",
		ConfPath:    "/etc/wireguard/wg0.conf",
		SidecarPath: "/etc/wgpeer/wg0.toml",
		BackupPath:  "", // --no-backup
		ConfExists:  true, SidecarExists: true,
	}
	var out strings.Builder
	confirmRemove(strings.NewReader("n\n"), &out, plan)
	if !strings.Contains(out.String(), "NO backup") {
		t.Errorf("summary should warn about the missing backup:\n%s", out.String())
	}
}
