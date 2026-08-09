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

// TestSplitMode covers the top-level dispatch, in particular the shorthand that
// lets the daily-driver client half be typed without the "client" word.
func TestSplitMode(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantMode string
		wantRest []string
	}{
		{
			name:     "explicit server mode",
			args:     []string{"server", "--iface", "wg0", "add"},
			wantMode: "server", wantRest: []string{"--iface", "wg0", "add"},
		},
		{
			name:     "explicit client mode",
			args:     []string{"client", "add", "bob"},
			wantMode: "client", wantRest: []string{"add", "bob"},
		},
		{
			name:     "shorthand: bare add implies client, subcommand kept",
			args:     []string{"add", "bob", "--iface", "wg1"},
			wantMode: "client", wantRest: []string{"add", "bob", "--iface", "wg1"},
		},
		{
			name:     "shorthand: bare list",
			args:     []string{"list", "--json"},
			wantMode: "client", wantRest: []string{"list", "--json"},
		},
		{
			name:     "shorthand: bare kill",
			args:     []string{"kill", "bob"},
			wantMode: "client", wantRest: []string{"kill", "bob"},
		},
		{
			name:     "shorthand: bare rename",
			args:     []string{"rename", "bob", "боб"},
			wantMode: "client", wantRest: []string{"rename", "bob", "боб"},
		},
		{name: "help flag", args: []string{"--help"}, wantMode: "help"},
		{name: "help word", args: []string{"help"}, wantMode: "help"},
		{
			// A typo must NOT be swept into client mode — it stays unknown, so the
			// user gets "unknown mode" instead of a baffling client-side error.
			name:     "typo stays unknown",
			args:     []string{"addd", "bob"},
			wantMode: "", wantRest: []string{"addd", "bob"},
		},
		{
			// provide/remove are server-only; Main turns this into a pointed hint.
			name:     "server-only subcommand is not client shorthand",
			args:     []string{"provide", "wg0"},
			wantMode: "", wantRest: []string{"provide", "wg0"},
		},
		{name: "no args", args: nil, wantMode: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, rest := splitMode(tt.args)
			if mode != tt.wantMode {
				t.Errorf("mode = %q, want %q", mode, tt.wantMode)
			}
			if !slices.Equal(rest, tt.wantRest) {
				t.Errorf("rest = %v, want %v", rest, tt.wantRest)
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
