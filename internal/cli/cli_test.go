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
