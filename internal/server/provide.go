//go:build linux

package server

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// DefaultWGDir is where wg-quick expects interface .conf files. Overridable via
// WGPEER_WG_DIR (tests, unusual layouts).
const DefaultWGDir = "/etc/wireguard"

// Provisioned listen ports are drawn from this half-open range when the caller
// does not pin one — "a random high port" per the feature brief. The band sits
// above the well-known/registered clutter and mostly clear of the Linux
// ephemeral range, so a fresh interface rarely clashes with an outbound socket.
const (
	minAutoPort = 20000
	maxAutoPort = 60000
)

// WGDir returns the directory holding wg-quick .conf files.
func WGDir() string {
	if d := os.Getenv("WGPEER_WG_DIR"); d != "" {
		return d
	}
	return DefaultWGDir
}

// detectGlobalV4 and runEnable are indirected through vars so tests can stub the
// two host-dependent side effects (interface enumeration and systemd).
var (
	detectGlobalV4 = globalV4Addrs
	runEnable      = enableWgQuick
)

// ProvideOptions parameterises interface provisioning. The command layer parses
// flags into this; unset numeric/zero fields mean "invent a sensible default".
type ProvideOptions struct {
	Iface      string
	Subnet     netip.Prefix // required; the peer address pool (v4-only in v1)
	Address    netip.Addr   // server's own address inside Subnet; zero = first host
	ListenPort int          // 0 = random high port
	Endpoint   string       // "host" or "host:port" advertised to clients; "" = auto-detect
	Up         bool         // run `systemctl enable --now wg-quick@<iface>`

	// Client-template knobs baked into the sidecar. Empty AllowedIPs defaults to
	// full-tunnel; empty DNS / zero MTU / zero Keepalive are written as "unset"
	// (the client omits the line and keeps its own resolver / lets wg-quick derive
	// the MTU / sends no keepalive).
	AllowedIPs []string
	DNS        []string
	MTU        int
	Keepalive  int

	WGDir      string // "" = WGDir()
	SidecarDir string // "" = config.ServerDir()
}

// Provide bootstraps a brand-new interface: it invents the missing bits (server
// address, listen port, endpoint menu, keypair), writes /etc/wireguard/<iface>.conf
// and the /etc/wgpeer/<iface>.toml sidecar atomically, and — unless Up is false —
// brings the interface up and enables it at boot via wg-quick.
//
// It refuses to touch an interface whose conf or sidecar already exists, so a
// re-run never clobbers a live config. Every failure returns a ProvideResponse
// with OK=false; the caller emits it as JSON exactly like the other server ops.
func Provide(opts ProvideOptions) protocol.ProvideResponse {
	if err := validIface(opts.Iface); err != nil {
		return provErr(protocol.ErrBadRequest, err.Error())
	}
	if !opts.Subnet.IsValid() {
		return provErr(protocol.ErrBadRequest, "a subnet is required (--net <CIDR>)")
	}
	subnet := opts.Subnet.Masked()
	if !subnet.Addr().Is4() {
		return provErr(protocol.ErrBadRequest, "subnet must be IPv4 (v1 is v4-only)")
	}
	if subnet.Bits() > 30 {
		return provErr(protocol.ErrBadRequest, fmt.Sprintf("subnet %s is too small to host a server and peers", subnet))
	}

	// Server address: the caller's choice, or the first host of the subnet.
	serverAddr := opts.Address
	if serverAddr.IsValid() {
		if !subnet.Contains(serverAddr) {
			return provErr(protocol.ErrBadRequest, fmt.Sprintf("address %s is not inside subnet %s", serverAddr, subnet))
		}
	} else {
		serverAddr = subnet.Addr().Next() // .1 for a conventional prefix
	}

	// Listen port: the caller's choice, or a random high one.
	port := opts.ListenPort
	if port == 0 {
		p, err := randomPort()
		if err != nil {
			return provErr(protocol.ErrInternal, "picking a listen port: "+err.Error())
		}
		port = p
	} else if port < 1 || port > 65535 {
		return provErr(protocol.ErrBadRequest, fmt.Sprintf("listen port %d out of range", port))
	}

	// Endpoint menu: an explicit --endpoint, or auto-detected public IPv4s.
	endpoints, errResp := resolveEndpoints(opts.Endpoint, port)
	if errResp != nil {
		return *errResp
	}

	wgDir := opts.WGDir
	if wgDir == "" {
		wgDir = WGDir()
	}
	sidecarDir := opts.SidecarDir
	if sidecarDir == "" {
		sidecarDir = config.ServerDir()
	}
	confPath := filepath.Join(wgDir, opts.Iface+".conf")
	sidecarPath := filepath.Join(sidecarDir, opts.Iface+".toml")

	// Never clobber an interface that already exists (either half is enough).
	if err := mustNotExist(confPath); err != nil {
		return provErr(protocol.ErrBadRequest, err.Error())
	}
	if err := mustNotExist(sidecarPath); err != nil {
		return provErr(protocol.ErrBadRequest, err.Error())
	}

	priv, err := wgkey.GeneratePrivateKey()
	if err != nil {
		return provErr(protocol.ErrInternal, "generating server key: "+err.Error())
	}
	pub, err := wgkey.PublicKey(priv)
	if err != nil {
		return provErr(protocol.ErrInternal, "deriving server public key: "+err.Error())
	}

	allowedIPs := opts.AllowedIPs
	if len(allowedIPs) == 0 {
		allowedIPs = fullTunnel()
	}
	tmpl := sidecarTemplate{AllowedIPs: allowedIPs, DNS: opts.DNS, MTU: opts.MTU, Keepalive: opts.Keepalive}

	confText := renderInterfaceConf(opts.Iface, serverAddr, subnet.Bits(), port, wgkey.Encode(priv))
	sidecarText := renderSidecar(opts.Iface, confPath, subnet, serverAddr, tmpl, endpoints)

	if err := os.MkdirAll(wgDir, 0o700); err != nil { // holds the private key
		return provErr(protocol.ErrInternal, "creating "+wgDir+": "+err.Error())
	}
	if err := os.MkdirAll(sidecarDir, 0o755); err != nil {
		return provErr(protocol.ErrInternal, "creating "+sidecarDir+": "+err.Error())
	}
	if err := atomicWrite(confPath, []byte(confText), 0o600); err != nil {
		return provErr(protocol.ErrInternal, "writing "+confPath+": "+err.Error())
	}
	if err := atomicWrite(sidecarPath, []byte(sidecarText), 0o644); err != nil {
		return provErr(protocol.ErrInternal, "writing "+sidecarPath+": "+err.Error())
	}

	resp := protocol.ProvideResponse{
		Status:              protocol.Status{OK: true},
		Iface:               opts.Iface,
		ConfPath:            confPath,
		SidecarPath:         sidecarPath,
		Subnet:              subnet.String(),
		Address:             fmt.Sprintf("%s/%d", serverAddr, subnet.Bits()),
		ListenPort:          port,
		ServerPublicKey:     wgkey.Encode(pub),
		Endpoints:           endpoints,
		AllowedIPs:          allowedIPs,
		DNS:                 opts.DNS,
		MTU:                 opts.MTU,
		PersistentKeepalive: opts.Keepalive,
	}

	if opts.Up {
		if err := runEnable(opts.Iface); err != nil {
			// The files are already on disk; report the failure but keep the
			// details so the admin can bring it up by hand.
			resp.Status = protocol.Status{
				OK:      false,
				Error:   protocol.ErrInternal,
				Message: "config written but bring-up failed: " + err.Error(),
			}
			return resp
		}
		resp.Enabled = true
	}
	return resp
}

// resolveEndpoints builds the endpoint menu. An explicit host (optionally with a
// :port) yields a single "public" entry; otherwise every non-private IPv4 found
// on a local interface becomes an entry named after that interface. No public
// IPv4 at all is a hard failure — a server no client can dial is useless.
func resolveEndpoints(explicit string, port int) ([]protocol.Endpoint, *protocol.ProvideResponse) {
	if explicit != "" {
		addr := explicit
		if _, _, err := net.SplitHostPort(explicit); err != nil {
			addr = fmt.Sprintf("%s:%d", explicit, port) // no port given → append ours
		}
		return []protocol.Endpoint{{Name: "public", Addr: addr}}, nil
	}
	found, err := detectGlobalV4()
	if err != nil {
		e := provErr(protocol.ErrInternal, "enumerating interfaces: "+err.Error())
		return nil, &e
	}
	if len(found) == 0 {
		e := provErr(protocol.ErrBadRequest, "no non-private IPv4 address found on any interface; pass --endpoint <host>")
		return nil, &e
	}
	eps := make([]protocol.Endpoint, len(found))
	for i, na := range found {
		eps[i] = protocol.Endpoint{Name: na.Iface, Addr: fmt.Sprintf("%s:%d", na.IP, port)}
	}
	return eps, nil
}

// renderInterfaceConf builds the fresh [Interface] block. It is written once and
// thereafter treated as verbatim/opinionated by the rest of wgpeer (spec §7): the
// Address carries the subnet prefix so wg-quick installs the pool route.
func renderInterfaceConf(iface string, addr netip.Addr, bits, port int, privKey string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "# %s — provisioned by `wgpeer server provide`. Edit as needed;\n", iface)
	fmt.Fprintf(&b, "# wgpeer preserves this [Interface] verbatim and never regenerates it.\n")
	fmt.Fprintf(&b, "Address = %s/%d\n", addr, bits)
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	fmt.Fprintf(&b, "PrivateKey = %s\n", privKey)
	return b.String()
}

// sidecarTemplate carries the client-facing [template] knobs. A zero value in
// DNS/MTU/Keepalive means "unset" — the line is dropped and the client supplies
// its own (spec §9; client.go omits an empty/zero field).
type sidecarTemplate struct {
	AllowedIPs []string
	DNS        []string
	MTU        int
	Keepalive  int
}

// renderSidecar builds the /etc/wgpeer/<iface>.toml sidecar as a commented
// template mirroring examples/wg0.toml, so the generated file is as readable as
// a hand-written one and round-trips through config.LoadServer.
//
// DNS, MTU, and persistent_keepalive are omitted when unset: the server is not a
// resolver, an unset MTU lets the client's wg-quick derive the right one from its
// route (the wireguard-over-ethernet default), and keepalive is only needed
// behind NAT. Each is left as an explanatory comment so the admin sees the knob.
func renderSidecar(iface, confPath string, subnet netip.Prefix, serverAddr netip.Addr, t sidecarTemplate, endpoints []protocol.Endpoint) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Server config for interface %s — generated by `wgpeer server provide`.\n", iface)
	fmt.Fprintf(&b, "# The interface name comes from the filename. Edit freely.\n\n")
	fmt.Fprintf(&b, "conf_path = %q # source of truth for peers\n", confPath)
	fmt.Fprintf(&b, "subnet    = %q # address pool for peers (v4-only in v1)\n", subnet.String())
	fmt.Fprintf(&b, "reserved  = [%q] # the server's own address, kept out of the pool\n\n", serverAddr.String())
	fmt.Fprintf(&b, "[template] # server-owned defaults baked into each client config\n")
	if len(t.DNS) > 0 {
		fmt.Fprintf(&b, "dns                  = [%s]\n", quoteJoin(t.DNS))
	} else {
		fmt.Fprintf(&b, "# dns unset — client keeps its own resolver (provision with --dns to push one)\n")
	}
	fmt.Fprintf(&b, "allowed_ips          = [%s]%s\n", quoteJoin(t.AllowedIPs), tunnelComment(t.AllowedIPs))
	if t.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive = %d\n", t.Keepalive)
	} else {
		fmt.Fprintf(&b, "# persistent_keepalive unset — set --keepalive (e.g. 25) for peers behind NAT\n")
	}
	if t.MTU > 0 {
		fmt.Fprintf(&b, "mtu                  = %d\n", t.MTU)
	} else {
		fmt.Fprintf(&b, "# mtu unset — client's wg-quick derives it from the route (provision with --mtu to pin)\n")
	}
	fmt.Fprintf(&b, "psk_default          = true\n\n")
	fmt.Fprintf(&b, "# Endpoint menu (what clients dial; first is the default).\n")
	for _, e := range endpoints {
		fmt.Fprintf(&b, "[[endpoint]]\n")
		fmt.Fprintf(&b, "name = %q\n", e.Name)
		fmt.Fprintf(&b, "addr = %q\n", e.Addr)
	}
	return b.String()
}

// fullTunnel is the default AllowedIPs pushed to clients (route everything).
func fullTunnel() []string { return []string{"0.0.0.0/0", "::/0"} }

// ResolveAllowedIPs turns the --allowed-ips flag value into a concrete list. The
// keyword "subnet" expands to the provisioned pool (split-tunnel to the VPN
// network only — a common case); otherwise it is a comma-separated CIDR list,
// each entry validated as a prefix.
func ResolveAllowedIPs(flag string, subnet netip.Prefix) ([]string, error) {
	if strings.TrimSpace(flag) == "subnet" {
		return []string{subnet.Masked().String()}, nil
	}
	var out []string
	for _, p := range strings.Split(flag, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			return nil, fmt.Errorf("bad AllowedIPs entry %q: %w", p, err)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--allowed-ips is empty")
	}
	return out, nil
}

// quoteJoin renders a string slice as a TOML array body: "a", "b", "c".
func quoteJoin(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}

// tunnelComment labels the allowed_ips line as full- or split-tunnel.
func tunnelComment(allowed []string) string {
	for _, a := range allowed {
		if a == "0.0.0.0/0" {
			return " # full-tunnel by default"
		}
	}
	return " # split-tunnel (only these routes go through the VPN)"
}

// namedAddr pairs a detected address with the interface it came from.
type namedAddr struct {
	Iface string
	IP    netip.Addr
}

// globalV4Addrs returns the non-private, globally-routable IPv4 addresses across
// all up interfaces, each tagged with its interface name.
func globalV4Addrs() ([]namedAddr, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []namedAddr
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue // a single flaky interface should not abort detection
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !isPublicV4(ip) {
				continue
			}
			na, ok := netip.AddrFromSlice(ip.To4())
			if !ok {
				continue
			}
			out = append(out, namedAddr{Iface: ifi.Name, IP: na})
		}
	}
	return out, nil
}

// isPublicV4 reports whether ip is a globally-routable, non-private IPv4 address
// — i.e. a plausible WireGuard endpoint. IsGlobalUnicast already rules out
// loopback, link-local, multicast and the unspecified address.
func isPublicV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4.IsGlobalUnicast() && !v4.IsPrivate()
}

// randomPort returns a uniformly random port in [minAutoPort, maxAutoPort).
func randomPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxAutoPort-minAutoPort)))
	if err != nil {
		return 0, err
	}
	return minAutoPort + int(n.Int64()), nil
}

// enableWgQuick brings the interface up now and enables it at boot in one step.
func enableWgQuick(iface string) error {
	var errb bytes.Buffer
	cmd := exec.Command("systemctl", "enable", "--now", "wg-quick@"+iface)
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl enable --now wg-quick@%s: %w: %s", iface, err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// mustNotExist errors if path already exists (a stat error other than NotExist
// is surfaced too — better to refuse than to overwrite blindly).
func mustNotExist(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite (remove it first to re-provision)", path)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("checking %s: %w", path, err)
	}
	return nil
}

// validIface checks an interface name against wg-quick's accepted form: 1–15
// chars from [A-Za-z0-9_=+.-]. Rejecting junk here keeps it out of a filename
// and a systemd unit name.
func validIface(name string) error {
	if name == "" {
		return fmt.Errorf("interface name is required")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name %q is too long (max 15 chars)", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '=' || r == '+' || r == '.' || r == '-':
		default:
			return fmt.Errorf("interface name %q has an invalid character %q", name, r)
		}
	}
	return nil
}

func provErr(code, msg string) protocol.ProvideResponse {
	return protocol.ProvideResponse{Status: protocol.Status{OK: false, Error: code, Message: msg}}
}
