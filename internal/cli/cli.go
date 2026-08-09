// Package cli wires the two wgpeer modes to the terminal (spec §2, §6):
//
//	wgpeer server --iface <wgN> <add|list|kill|rename>   # headless: stdin JSON → stdout JSON
//	wgpeer client <add|list|kill|rename> [flags] [name]  # keygen + ssh + QR
//
// The `client` word is optional: a bare `wgpeer add bob` means `wgpeer client
// add bob`, since the client half is the one typed daily (see splitMode).
//
// This file holds everything that builds everywhere. The server half lives in
// server.go behind `linux && !clientonly`, with server_stub.go standing in for
// it elsewhere: on a non-Linux box (or with -tags clientonly) wgpeer is a pure
// client that drives a Linux server over ssh.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/akovalenko/wgpeer/internal/client"
	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
)

// Main is the process entry point; it returns the exit code.
func Main(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	mode, rest := splitMode(args)
	switch mode {
	case "server":
		return serverMain(rest)
	case "client":
		return clientMain(rest)
	case "help":
		usage()
		return 0
	default:
		// provide/remove are server-only, so they get a pointed hint rather than
		// being swept into the client shorthand below.
		if args[0] == protocol.OpProvide || args[0] == protocol.OpRemove {
			fmt.Fprintf(os.Stderr, "wgpeer: %s is a server subcommand — did you mean `wgpeer server %s`?\n", args[0], args[0])
			return 2
		}
		fmt.Fprintf(os.Stderr, "wgpeer: unknown mode %q\n", args[0])
		usage()
		return 2
	}
}

// splitMode maps the top-level argv onto a mode ("server", "client", "help", or
// "" for unrecognised) and the arguments that mode should parse.
//
// The wrinkle is the shorthand: a bare client subcommand at the front implies
// client mode, so `wgpeer add bob` == `wgpeer client add bob`. Only the known
// client subcommands trigger it — a typo stays an unknown mode rather than
// becoming a baffling client-side error. Nothing regresses: `wgpeer add` was
// never valid before.
func splitMode(args []string) (mode string, rest []string) {
	if len(args) == 0 {
		return "", nil
	}
	switch args[0] {
	case "server":
		return "server", args[1:]
	case "client":
		return "client", args[1:]
	case "-h", "--help", "help":
		return "help", nil
	}
	if isClientCommand(args[0]) {
		return "client", args // the subcommand itself stays in rest
	}
	return "", args
}

// isClientCommand reports whether s is a `wgpeer client` subcommand.
func isClientCommand(s string) bool {
	switch s {
	case protocol.OpAdd, protocol.OpList, protocol.OpKill, protocol.OpRename:
		return true
	}
	return false
}

// usage prints the help text. The server-mode section is build-dependent
// (serverUsage), so a client-only binary never advertises commands it does not
// carry.
func usage() {
	fmt.Fprint(os.Stderr, `wgpeer — WireGuard peer manager
`+serverUsage()+`
  wgpeer client <cmd> [flags] [name]
      add  <name> [--server S] [--iface I] [--endpoint NAME] [--no-psk]
                  [--split] [--qr always|never] [--qr-png FILE] [--invert]
           The config goes to stdout and the terminal QR to stderr, so
           "add ... > foo.conf" yields just the config.
      list        [--server S] [--iface I] [--json]
      kill <name> [--server S] [--iface I]
      rename <old> <new> [--server S] [--iface I]
           Relabel a peer; its key, PSK and address are untouched, so configs
           already handed out keep working. Quote names containing spaces.

      "client" is optional: `+"`wgpeer add bob`"+` == `+"`wgpeer client add bob`"+`.
`)
}

// --- client mode ---------------------------------------------------------

func clientMain(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case protocol.OpAdd:
		return clientAdd(args[1:])
	case protocol.OpList:
		return clientList(args[1:])
	case protocol.OpKill:
		return clientKill(args[1:])
	case protocol.OpRename:
		return clientRename(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "wgpeer client: unknown command %q\n", args[0])
		usage()
		return 2
	}
}

// resolveClient loads the client menu and resolves the server entry + iface.
func resolveClient(server, iface string) (*client.Client, error) {
	cfg, err := config.LoadClient()
	if err != nil {
		return nil, err
	}
	entry, ifc, err := cfg.Resolve(server, iface)
	if err != nil {
		return nil, err
	}
	return client.NewSSH(client.SSHConfig{
		Command:    entry.SSHCommand,
		Target:     entry.SSH,
		Sudo:       entry.Sudo,
		WgpeerPath: entry.WgpeerPath,
	}, ifc), nil
}

func clientAdd(args []string) int {
	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	server := fs.String("server", "", "server name from the client menu")
	iface := fs.String("iface", "", "interface name on the server")
	endpoint := fs.String("endpoint", "", "endpoint menu name (default: first)")
	noPSK := fs.Bool("no-psk", false, "do not generate a preshared key")
	split := fs.Bool("split", false, "split tunnel: route only the server subnet")
	qrMode := fs.String("qr", "always", "draw the terminal QR on stderr: always or never")
	qrPNG := fs.String("qr-png", "", "also write the QR to this PNG file")
	qrSize := fs.Int("qr-size", 256, "PNG QR size in pixels (with --qr-png)")
	invert := fs.Bool("invert", false, "invert QR colours for light-on-dark terminals")
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	name := joinArgs(positionals)
	if name == "" {
		fmt.Fprintln(os.Stderr, "wgpeer client add: a peer name is required")
		return 2
	}

	// Validate output options before any keygen or server round-trip, so a bad
	// flag never leaves a stray peer behind.
	showQR, err := resolveTerminalQR(*qrMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer client add: %v\n", err)
		return 2
	}

	cl, err := resolveClient(*server, *iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	cfgText, _, err := cl.Add(client.AddOptions{
		Name:     name,
		Endpoint: *endpoint,
		NoPSK:    *noPSK,
		Split:    *split,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}

	// The config is the machine-consumable artifact → stdout.
	fmt.Print(cfgText)

	if *qrPNG != "" {
		if err := client.WriteQRPNG(cfgText, *qrPNG, *qrSize); err != nil {
			fmt.Fprintf(os.Stderr, "wgpeer: writing QR PNG: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote QR to %s\n", *qrPNG)
	}

	if showQR {
		qr, err := client.RenderTerminalQR(cfgText, *invert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wgpeer: rendering QR: %v\n", err)
			return 1
		}
		// QR is a human aid → stderr, so it never pollutes a redirected config.
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, qr)
	}
	return 0
}

func clientList(args []string) int {
	fs := flag.NewFlagSet("client list", flag.ContinueOnError)
	server := fs.String("server", "", "server name from the client menu")
	iface := fs.String("iface", "", "interface name on the server")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cl, err := resolveClient(*server, *iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	resp, err := cl.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	if *asJSON {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIP\tPSK\tPUBLIC KEY")
	for _, p := range resp.Peers {
		psk := "no"
		if p.PSK {
			psk = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.IP, psk, p.PublicKey)
	}
	tw.Flush()
	return 0
}

func clientKill(args []string) int {
	fs := flag.NewFlagSet("client kill", flag.ContinueOnError)
	server := fs.String("server", "", "server name from the client menu")
	iface := fs.String("iface", "", "interface name on the server")
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	name := joinArgs(positionals)
	if name == "" {
		fmt.Fprintln(os.Stderr, "wgpeer client kill: a peer name is required")
		return 2
	}
	cl, err := resolveClient(*server, *iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	resp, err := cl.Kill(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	fmt.Printf("removed %q (%s)\n", resp.Removed.Name, resp.Removed.PublicKey)
	return 0
}

// clientRename relabels a peer. Unlike add/kill it takes two names, so the
// "unquoted multi-word name" convenience (joinArgs) cannot apply — there is no
// way to tell where the old name ends and the new one begins. Hence exactly two
// positionals, with an error that says so.
func clientRename(args []string) int {
	fs := flag.NewFlagSet("client rename", flag.ContinueOnError)
	server := fs.String("server", "", "server name from the client menu")
	iface := fs.String("iface", "", "interface name on the server")
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 2 {
		fmt.Fprintf(os.Stderr, "wgpeer client rename: expected exactly two names, got %d\n", len(positionals))
		fmt.Fprintln(os.Stderr, `    wgpeer client rename <old> <new>      # quote names containing spaces`)
		return 2
	}
	from, to := positionals[0], positionals[1]

	cl, err := resolveClient(*server, *iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	resp, err := cl.Rename(from, to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: %v\n", err)
		return 1
	}
	fmt.Printf("renamed %q → %q (%s)\n", resp.Renamed.From, resp.Renamed.To, resp.Renamed.PublicKey)
	return 0
}

// parseInterspersed parses flags that may appear before or after the positional
// arguments, returning the positionals. The stdlib flag package stops at the
// first non-flag token; this loops past each positional and resumes parsing, so
// the documented "add <name> [flags]" syntax works (spec §6) — important when
// typing on a phone where flag order is easy to get wrong.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positionals, nil
		}
		positionals = append(positionals, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// joinArgs joins positional args with spaces so an unquoted multi-word peer
// name still works (a quoted "для Васи" arrives as one arg either way).
func joinArgs(args []string) string {
	return strings.Join(args, " ")
}

// resolveTerminalQR decides whether to draw the terminal QR (always written to
// stderr, so it never mixes with the config on stdout). Default is on; --qr never
// suppresses it.
func resolveTerminalQR(mode string) (bool, error) {
	switch mode {
	case "always":
		return true, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("--qr must be always or never")
	}
}
