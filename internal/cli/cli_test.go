package cli

import (
	"flag"
	"slices"
	"strings"
	"testing"

	"github.com/akovalenko/wgpeer/internal/server"
)

func TestParseInterspersed(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPos  []string
		wantIfce string
		wantPSK  bool
	}{
		{
			name:    "flags before name",
			args:    []string{"--iface", "wg1", "--no-psk", "bob"},
			wantPos: []string{"bob"}, wantIfce: "wg1", wantPSK: true,
		},
		{
			name:    "flags after name (spec §6 syntax)",
			args:    []string{"bob", "--iface", "wg1", "--no-psk"},
			wantPos: []string{"bob"}, wantIfce: "wg1", wantPSK: true,
		},
		{
			name:    "flags interspersed",
			args:    []string{"--iface", "wg1", "bob", "--no-psk"},
			wantPos: []string{"bob"}, wantIfce: "wg1", wantPSK: true,
		},
		{
			name:    "multi-word unquoted name with trailing flag",
			args:    []string{"my", "peer", "--iface", "wg1"},
			wantPos: []string{"my", "peer"}, wantIfce: "wg1",
		},
		{
			name:    "no flags",
			args:    []string{"alice"},
			wantPos: []string{"alice"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			iface := fs.String("iface", "", "")
			noPSK := fs.Bool("no-psk", false, "")
			pos, err := parseInterspersed(fs, tt.args)
			if err != nil {
				t.Fatalf("parseInterspersed: %v", err)
			}
			if !slices.Equal(pos, tt.wantPos) {
				t.Errorf("positionals = %v, want %v", pos, tt.wantPos)
			}
			if *iface != tt.wantIfce {
				t.Errorf("iface = %q, want %q", *iface, tt.wantIfce)
			}
			if *noPSK != tt.wantPSK {
				t.Errorf("no-psk = %v, want %v", *noPSK, tt.wantPSK)
			}
		})
	}
}

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

func TestResolveTerminalQR(t *testing.T) {
	tests := []struct {
		mode      string
		want      bool
		wantError bool
	}{
		{"always", true, false}, // default: draw on stderr
		{"never", false, false}, // suppressed
		{"bogus", false, true},  // invalid mode
	}
	for _, tt := range tests {
		got, err := resolveTerminalQR(tt.mode)
		if (err != nil) != tt.wantError {
			t.Errorf("resolveTerminalQR(%q) err=%v, wantError=%v", tt.mode, err, tt.wantError)
			continue
		}
		if got != tt.want {
			t.Errorf("resolveTerminalQR(%q) = %v, want %v", tt.mode, got, tt.want)
		}
	}
}
