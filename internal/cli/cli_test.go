package cli

import (
	"flag"
	"slices"
	"testing"
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

func TestResolveTerminalQR(t *testing.T) {
	tests := []struct {
		mode      string
		png       bool
		tty       bool
		want      bool
		wantError bool
	}{
		{"auto", false, true, true, false},    // interactive: show QR
		{"auto", false, false, false, false},  // piped/redirected: config only
		{"auto", true, true, false, false},    // PNG requested: no terminal QR
		{"always", false, false, true, false}, // forced on even when piped
		{"always", true, false, true, false},  // forced on alongside PNG
		{"never", false, true, false, false},  // forced off even on a TTY
		{"bogus", false, true, false, true},   // invalid mode
	}
	for _, tt := range tests {
		got, err := resolveTerminalQR(tt.mode, tt.png, tt.tty)
		if (err != nil) != tt.wantError {
			t.Errorf("resolveTerminalQR(%q,%v,%v) err=%v, wantError=%v", tt.mode, tt.png, tt.tty, err, tt.wantError)
			continue
		}
		if got != tt.want {
			t.Errorf("resolveTerminalQR(%q,%v,%v) = %v, want %v", tt.mode, tt.png, tt.tty, got, tt.want)
		}
	}
}
