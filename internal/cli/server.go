//go:build linux && !clientonly

package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/server"
)

// serverUsage is the server-mode half of the usage text. The client-only build
// replaces it with a note that the half is absent (see server_stub.go).
func serverUsage() string {
	return `
  wgpeer server --iface <wgN> <add|list|kill|rename>
      Headless privileged half (run under ssh+sudo). Reads a JSON request on
      stdin and writes a JSON response on stdout.

  wgpeer server provide <wgN> --net <CIDR> [--listen-port N] [--address IP]
                               [--endpoint HOST] [--allowed-ips LIST] [--dns LIST]
                               [--mtu N] [--keepalive N] [--no-up]
      Bootstrap a new interface: generate a key, write /etc/wireguard/<wgN>.conf
      and the /etc/wgpeer/<wgN>.toml sidecar, then (unless --no-up) enable and
      bring it up via wg-quick. --allowed-ips defaults to full-tunnel ("subnet"
      = split-tunnel to --net); --dns/--mtu/--keepalive are unset unless given.
      JSON on stdout, human summary on stderr.

  wgpeer server remove <wgN> [--yes] [--no-backup]
      Tear an interface down (inverse of provide): stop and disable wg-quick,
      then delete /etc/wireguard/<wgN>.conf and /etc/wgpeer/<wgN>.toml. Prompts
      for confirmation first (needs a terminal on stdin; --yes skips it). Backs
      up the key-bearing .conf to <conf>.bak-YYYYMMDD unless --no-backup.
      JSON on stdout, human summary on stderr.
`
}

func serverMain(args []string) int {
	// `provide` and `remove` are the whole-interface subcommands: they take a
	// positional iface and CLI flags (no stdin JSON), so they are dispatched before
	// the --iface/JSON request path used by add/list/kill.
	if len(args) > 0 && args[0] == protocol.OpProvide {
		return provideMain(args[1:])
	}
	if len(args) > 0 && args[0] == protocol.OpRemove {
		return removeMain(args[1:])
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	iface := fs.String("iface", "", "wireguard interface name (selects /etc/wgpeer/<iface>.toml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "wgpeer server: expected a command (add|list|kill|rename)")
		return 2
	}
	op := rest[0]
	if *iface == "" {
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: "--iface is required"})
	}

	// add/list/kill read a JSON request on stdin; they are meant to be driven by
	// `wgpeer client` over ssh (a pipe), not typed at a terminal. Refuse an
	// interactive stdin so a hand-run does not silently hang on a blocking read.
	if stdinIsInteractive() {
		fmt.Fprintf(os.Stderr, "wgpeer server %s: this is the headless half — normally `wgpeer client %s` drives it over ssh, feeding a JSON request on stdin. Refusing to read from a terminal.\n", op, op)
		fmt.Fprintln(os.Stderr, "If you are poking it by hand, pipe the request in — yes, a genuine useless use of cat:")
		fmt.Fprintf(os.Stderr, "    echo '{\"op\":\"%s\"}' | wgpeer server --iface %s %s\n", op, *iface, op)
		return 2
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
	case protocol.OpRename:
		r := s.Rename(req)
		return emit(r)
	default:
		return emit(protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: "unknown command " + op})
	}
}

// provideMain parses `server provide <iface> --net <CIDR> [flags]` and bootstraps
// the interface. Output is dual: the ProvideResponse as JSON on stdout (for a
// future `client provide` wrapper) and a human summary on stderr (for a hand
// run). Genuine flag-syntax errors return exit 2; everything else — including a
// missing/bad --net — comes back as a JSON response so the wrapper always sees one.
func provideMain(args []string) int {
	fs := flag.NewFlagSet("server provide", flag.ContinueOnError)
	netFlag := fs.String("net", "", "peer address pool as a CIDR, e.g. 172.19.0.0/16 (required)")
	listenPort := fs.Int("listen-port", 0, "UDP listen port (default: a random high port)")
	address := fs.String("address", "", "server's own address inside --net (default: first host)")
	endpoint := fs.String("endpoint", "", "endpoint host or host:port clients dial (default: auto-detect public IPv4)")
	allowedIPs := fs.String("allowed-ips", "0.0.0.0/0,::/0", `AllowedIPs pushed to clients: a CIDR list, or "subnet" for split-tunnel to --net only (default: full-tunnel)`)
	dnsFlag := fs.String("dns", "", "comma-separated DNS servers pushed to clients (default: unset — client keeps its own)")
	mtu := fs.Int("mtu", 0, "client MTU pushed to clients (default: unset — wg-quick derives it)")
	keepalive := fs.Int("keepalive", 0, "client PersistentKeepalive seconds (default: unset — set e.g. 25 behind NAT)")
	noUp := fs.Bool("no-up", false, "only write the config files; do not enable/bring up the interface")
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		return emitProvide(provideBadRequest("expected exactly one interface name, e.g. `wgpeer server provide wg0 --net 172.19.0.0/16`"))
	}
	iface := positionals[0]

	if *netFlag == "" {
		return emitProvide(provideBadRequest("--net <CIDR> is required (e.g. 172.19.0.0/16)"))
	}
	subnet, err := netip.ParsePrefix(*netFlag)
	if err != nil {
		return emitProvide(provideBadRequest(fmt.Sprintf(
			"bad --net %q: %v; give a full CIDR like 172.19.0.0/16 (shorthand like 172.19/16 is not yet supported)",
			*netFlag, err)))
	}
	allowed, err := server.ResolveAllowedIPs(*allowedIPs, subnet)
	if err != nil {
		return emitProvide(provideBadRequest(err.Error()))
	}
	if *mtu < 0 {
		return emitProvide(provideBadRequest(fmt.Sprintf("--mtu %d must be positive", *mtu)))
	}
	if *keepalive < 0 {
		return emitProvide(provideBadRequest(fmt.Sprintf("--keepalive %d must be positive", *keepalive)))
	}
	opts := server.ProvideOptions{
		Iface:      iface,
		Subnet:     subnet,
		ListenPort: *listenPort,
		Endpoint:   *endpoint,
		AllowedIPs: allowed,
		DNS:        splitCSV(*dnsFlag),
		MTU:        *mtu,
		Keepalive:  *keepalive,
		Up:         !*noUp,
	}
	if *address != "" {
		a, err := netip.ParseAddr(*address)
		if err != nil {
			return emitProvide(provideBadRequest(fmt.Sprintf("bad --address %q: %v", *address, err)))
		}
		opts.Address = a
	}
	return emitProvide(server.Provide(opts))
}

// emitProvide writes the human summary to stderr and the JSON response to stdout,
// returning the process exit code.
func emitProvide(resp protocol.ProvideResponse) int {
	printProvideSummary(os.Stderr, resp)
	return emit(resp)
}

func provideBadRequest(msg string) protocol.ProvideResponse {
	return protocol.ProvideResponse{Status: protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: msg}}
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty items;
// an empty input yields nil (so an unset --dns stays unset).
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printProvideSummary renders the human-readable half of a provide result.
func printProvideSummary(w io.Writer, r protocol.ProvideResponse) {
	if !r.OK {
		fmt.Fprintf(w, "wgpeer server provide: %s\n", r.Message)
		return
	}
	fmt.Fprintf(w, "provisioned %s\n", r.Iface)
	fmt.Fprintf(w, "  subnet:      %s\n", r.Subnet)
	fmt.Fprintf(w, "  address:     %s\n", r.Address)
	fmt.Fprintf(w, "  listen port: %d\n", r.ListenPort)
	fmt.Fprintf(w, "  allowed-ips: %s\n", strings.Join(r.AllowedIPs, ", "))
	if len(r.DNS) > 0 {
		fmt.Fprintf(w, "  dns:         %s\n", strings.Join(r.DNS, ", "))
	}
	if r.MTU > 0 {
		fmt.Fprintf(w, "  mtu:         %d\n", r.MTU)
	}
	if r.PersistentKeepalive > 0 {
		fmt.Fprintf(w, "  keepalive:   %d\n", r.PersistentKeepalive)
	}
	fmt.Fprintf(w, "  public key:  %s\n", r.ServerPublicKey)
	for _, e := range r.Endpoints {
		fmt.Fprintf(w, "  endpoint:    %s → %s\n", e.Name, e.Addr)
	}
	fmt.Fprintf(w, "  conf:        %s\n", r.ConfPath)
	fmt.Fprintf(w, "  sidecar:     %s\n", r.SidecarPath)
	if r.Enabled {
		fmt.Fprintf(w, "  enabled:     yes (systemctl enable --now wg-quick@%s)\n", r.Iface)
	} else {
		fmt.Fprintf(w, "  enabled:     no — bring up with: systemctl enable --now wg-quick@%s\n", r.Iface)
	}
}

// removeMain parses `server remove <iface> [--yes] [--no-backup]` and tears the
// interface down (the inverse of provide). It is interactive by default: it prints
// what will be destroyed and reads a y/N confirmation from stdin, which is why —
// unlike the headless add/list/kill — it wants a terminal on stdin. A non-tty
// stdin without --yes is refused rather than silently proceeding or hanging.
// Output is dual like provide: RemoveResponse as JSON on stdout, human summary on
// stderr.
func removeMain(args []string) int {
	fs := flag.NewFlagSet("server remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the confirmation prompt (for automation)")
	noBackup := fs.Bool("no-backup", false, "do NOT back up the .conf before deleting it (dangerous: the server private key lives only in the conf)")
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) != 1 {
		return emitRemove(removeBadRequest("expected exactly one interface name, e.g. `wgpeer server remove wg0`"))
	}
	opts := server.RemoveOptions{Iface: positionals[0], NoBackup: *noBackup}

	if !*yes {
		if !stdinIsInteractive() {
			return emitRemove(removeBadRequest("removal needs confirmation: pass --yes, or run it interactively with a terminal on stdin"))
		}
		// Resolve what will be destroyed and confirm before touching anything.
		plan, errResp := server.Plan(opts)
		if errResp != nil {
			return emitRemove(*errResp)
		}
		if !confirmRemove(os.Stdin, os.Stderr, plan) {
			return emitRemove(protocol.RemoveResponse{
				Status: protocol.Status{OK: false, Message: "cancelled — nothing was removed"},
				Iface:  plan.Iface,
			})
		}
	}
	return emitRemove(server.Remove(opts))
}

// confirmRemove prints the teardown summary to out and reads a y/N answer from in.
// Only "y"/"yes" (case-insensitive) confirms; empty, EOF, or anything else cancels
// — the safe default for a destructive, key-losing operation. It is split out (and
// takes its streams) so the prompt logic is unit-testable without a real terminal.
func confirmRemove(in io.Reader, out io.Writer, plan server.RemovePlan) bool {
	fmt.Fprintf(out, "wgpeer server remove %s — this will:\n", plan.Iface)
	fmt.Fprintf(out, "  • stop & disable  wg-quick@%s\n", plan.Iface)
	if plan.SidecarExists {
		fmt.Fprintf(out, "  • delete sidecar  %s\n", plan.SidecarPath)
	} else {
		fmt.Fprintf(out, "  • (no sidecar at  %s — skipping)\n", plan.SidecarPath)
	}
	if plan.ConfExists {
		fmt.Fprintf(out, "  • delete config   %s\n", plan.ConfPath)
	} else {
		fmt.Fprintf(out, "  • (no config at   %s — skipping)\n", plan.ConfPath)
	}
	if plan.BackupPath != "" {
		fmt.Fprintf(out, "  • back up config  %s → %s (0600, holds the private key)\n", plan.ConfPath, plan.BackupPath)
	} else if plan.ConfExists {
		fmt.Fprintf(out, "  • NO backup — the server private key will be lost irrecoverably\n")
	}
	fmt.Fprint(out, "Proceed? [y/N]: ")

	line, _ := bufio.NewReader(in).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

// emitRemove writes the human summary to stderr and the JSON response to stdout.
func emitRemove(resp protocol.RemoveResponse) int {
	printRemoveSummary(os.Stderr, resp)
	return emit(resp)
}

func removeBadRequest(msg string) protocol.RemoveResponse {
	return protocol.RemoveResponse{Status: protocol.Status{OK: false, Error: protocol.ErrBadRequest, Message: msg}}
}

// printRemoveSummary renders the human-readable half of a remove result.
func printRemoveSummary(w io.Writer, r protocol.RemoveResponse) {
	if !r.OK {
		fmt.Fprintf(w, "wgpeer server remove: %s\n", r.Message)
		return
	}
	fmt.Fprintf(w, "removed %s\n", r.Iface)
	if r.Disabled {
		fmt.Fprintf(w, "  disabled:   yes (systemctl disable --now wg-quick@%s)\n", r.Iface)
	} else {
		fmt.Fprintf(w, "  disabled:   no (was not enabled/active, or disable failed — see notes)\n")
	}
	for _, p := range r.Removed {
		fmt.Fprintf(w, "  deleted:    %s\n", p)
	}
	if r.BackupPath != "" {
		fmt.Fprintf(w, "  backup:     %s\n", r.BackupPath)
	} else {
		fmt.Fprintf(w, "  backup:     none (--no-backup)\n")
	}
	if r.Message != "" {
		fmt.Fprintf(w, "  notes:      %s\n", r.Message)
	}
}

// stdinIsInteractive reports whether stdin is a terminal (no piped request).
// A char device (tty) reads as interactive; a pipe or regular file — the client
// over ssh, or a shell redirect — does not, so the wrapper path is never
// blocked. (A `< /dev/null` redirect also reads as a char device, but the
// advised workaround is to pipe input, which is correctly detected.)
func stdinIsInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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
	case protocol.RenameResponse:
		return r.OK, true
	case protocol.ProvideResponse:
		return r.OK, true
	case protocol.RemoveResponse:
		return r.OK, true
	default:
		return false, false
	}
}
