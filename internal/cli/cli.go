// Package cli wires the two wgpeer modes to the terminal (spec §2, §6):
//
//	wgpeer server --iface <wgN> <add|list|kill>   # headless: stdin JSON → stdout JSON
//	wgpeer client <add|list|kill> [flags] [name]  # keygen + ssh + QR
package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/akovalenko/wgpeer/internal/client"
	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/server"
)

// Main is the process entry point; it returns the exit code.
func Main(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "server":
		return serverMain(args[1:])
	case "client":
		return clientMain(args[1:])
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "wgpeer: unknown mode %q\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `wgpeer — WireGuard peer manager

  wgpeer server --iface <wgN> <add|list|kill>
      Headless privileged half (run under ssh+sudo). Reads a JSON request on
      stdin and writes a JSON response on stdout.

  wgpeer client <cmd> [flags] [name]
      add  <name> [--server S] [--iface I] [--endpoint NAME] [--no-psk]
                  [--split] [--qr-png FILE] [--invert]
      list        [--server S] [--iface I] [--json]
      kill <name> [--server S] [--iface I]
`)
}

// --- server mode ---------------------------------------------------------

func serverMain(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	iface := fs.String("iface", "", "wireguard interface name (selects /etc/wgpeer/<iface>.toml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "wgpeer server: expected a command (add|list|kill)")
		return 2
	}
	op := rest[0]
	if *iface == "" {
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: "--iface is required"})
	}

	cfg, err := config.LoadServer(*iface)
	if err != nil {
		// Missing/invalid config = refusal to operate on this interface (spec §4.1).
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: err.Error()})
	}

	req, err := readRequest()
	if err != nil {
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: err.Error()})
	}
	req.Op = op // the subcommand is authoritative

	s := server.New(cfg)
	switch op {
	case protocol.OpAdd:
		r := s.Add(req)
		return emit(r)
	case protocol.OpList:
		r := s.List()
		return emit(r)
	case protocol.OpKill:
		r := s.Kill(req)
		return emit(r)
	default:
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: "unknown command " + op})
	}
}

// readRequest reads an optional JSON request from stdin (list sends none).
func readRequest() (protocol.Request, error) {
	var req protocol.Request
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return req, fmt.Errorf("reading stdin: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return req, fmt.Errorf("invalid request JSON: %w", err)
	}
	return req, nil
}

// emit writes the response as JSON to stdout and returns the exit code:
// 0 when ok, 1 otherwise (spec §5, §11). It accepts anything with an embedded
// Status so a single helper covers every response type.
func emit(resp any) int {
	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: marshalling response: %v\n", err)
		return 1
	}
	fmt.Println(string(out))
	if ok, _ := okOf(resp); ok {
		return 0
	}
	return 1
}

// okOf extracts the OK flag from any response carrying a protocol.Status.
func okOf(resp any) (bool, bool) {
	switch r := resp.(type) {
	case protocol.Status:
		return r.OK, true
	case protocol.AddResponse:
		return r.OK, true
	case protocol.ListResponse:
		return r.OK, true
	case protocol.KillResponse:
		return r.OK, true
	default:
		return false, false
	}
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
	return client.NewSSH(entry.SSH, entry.Sudo, ifc), nil
}

func clientAdd(args []string) int {
	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	server := fs.String("server", "", "server name from the client menu")
	iface := fs.String("iface", "", "interface name on the server")
	endpoint := fs.String("endpoint", "", "endpoint menu name (default: first)")
	noPSK := fs.Bool("no-psk", false, "do not generate a preshared key")
	split := fs.Bool("split", false, "split tunnel: route only the server subnet")
	qrPNG := fs.String("qr-png", "", "write the QR to this PNG file instead of the terminal")
	qrSize := fs.Int("qr-size", 256, "PNG QR size in pixels (with --qr-png)")
	invert := fs.Bool("invert", false, "invert QR colours for light-on-dark terminals")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	name := joinArgs(fs.Args())
	if name == "" {
		fmt.Fprintln(os.Stderr, "wgpeer client add: a peer name is required")
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

	fmt.Print(cfgText)
	if *qrPNG != "" {
		if err := client.WriteQRPNG(cfgText, *qrPNG, *qrSize); err != nil {
			fmt.Fprintf(os.Stderr, "wgpeer: writing QR PNG: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "wrote QR to %s\n", *qrPNG)
		return 0
	}
	qr, err := client.RenderTerminalQR(cfgText, *invert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgpeer: rendering QR: %v\n", err)
		return 1
	}
	fmt.Println()
	fmt.Println(qr)
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	name := joinArgs(fs.Args())
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

// joinArgs joins positional args with spaces so an unquoted multi-word peer
// name still works (a quoted "для Васи" arrives as one arg either way).
func joinArgs(args []string) string {
	return strings.Join(args, " ")
}
