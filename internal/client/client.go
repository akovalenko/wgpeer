// Package client implements the unprivileged half of wgpeer (spec §2, §6): it
// generates the private key locally (never sent anywhere), drives the server
// over ssh, and assembles the final client config + QR from the response.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgconf"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// Client drives one server interface. Exec runs `wgpeer server …` remotely,
// sending the request JSON on stdin and returning its stdout; it is a field so
// tests can substitute an in-process server.
type Client struct {
	SSHCommand []string // ssh invocation + flags; empty → ["ssh"]
	SSHTarget  string
	Sudo       bool
	WgpeerPath string // remote wgpeer binary; empty → "wgpeer" (PATH)
	Iface      string
	Exec       func(op string, reqJSON []byte) (stdout []byte, err error)
}

// SSHConfig describes how to reach a server's wgpeer over ssh. Command and
// WgpeerPath are optional (see config.ServerEntry); zero values reproduce the
// plain `ssh <target> wgpeer …` invocation.
type SSHConfig struct {
	Command    []string
	Target     string
	Sudo       bool
	WgpeerPath string
}

// NewSSH builds a Client whose Exec shells out to the system ssh (honouring
// ~/.ssh/config, agent, aliases — spec §14), plus any per-server ssh-command or
// remote-path overrides.
func NewSSH(cfg SSHConfig, iface string) *Client {
	c := &Client{
		SSHCommand: cfg.Command,
		SSHTarget:  cfg.Target,
		Sudo:       cfg.Sudo,
		WgpeerPath: cfg.WgpeerPath,
		Iface:      iface,
	}
	c.Exec = c.sshExec
	return c
}

// sshArgv builds the full command line: the ssh invocation, the target, then the
// remote `[sudo] <wgpeer> server --iface <iface> <op>`. Split out from sshExec so
// the argv can be unit-tested without spawning ssh. SSHCommand defaults to ["ssh"]
// and WgpeerPath to "wgpeer" (found on the login PATH).
func (c *Client) sshArgv(op string) []string {
	ssh := c.SSHCommand
	if len(ssh) == 0 {
		ssh = []string{"ssh"}
	}
	wgpeer := c.WgpeerPath
	if wgpeer == "" {
		wgpeer = "wgpeer"
	}
	argv := append([]string{}, ssh...) // fresh slice; never alias c.SSHCommand
	argv = append(argv, c.SSHTarget)
	if c.Sudo {
		argv = append(argv, "sudo")
	}
	argv = append(argv, wgpeer, "server", "--iface", c.Iface, op)
	return argv
}

func (c *Client) sshExec(op string, reqJSON []byte) ([]byte, error) {
	argv := c.sshArgv(op)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(reqJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	// The server prints a JSON response even when it exits non-zero, so prefer
	// stdout when it has content; only surface ssh/transport errors otherwise.
	if stdout.Len() == 0 && err != nil {
		return nil, fmt.Errorf("ssh %s: %w: %s", c.SSHTarget, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// AddOptions are the client-owned overrides for an add (spec §6, §9).
type AddOptions struct {
	Name     string
	Endpoint string // menu name; "" selects the default (first)
	NoPSK    bool
	Split    bool // route only the server subnet instead of full-tunnel
}

// Add generates a keypair (+PSK unless NoPSK), asks the server to register the
// public key, and assembles the client config. The private key stays local.
func (c *Client) Add(opts AddOptions) (configText string, resp protocol.AddResponse, err error) {
	if err := wgconf.ValidPeerName(opts.Name); err != nil {
		return "", resp, fmt.Errorf("invalid name: %w", err)
	}
	priv, err := wgkey.GeneratePrivateKey()
	if err != nil {
		return "", resp, err
	}
	pub, err := wgkey.PublicKey(priv)
	if err != nil {
		return "", resp, err
	}
	var psk string
	if !opts.NoPSK {
		k, err := wgkey.GeneratePSK()
		if err != nil {
			return "", resp, err
		}
		psk = wgkey.Encode(k)
	}

	// Endpoint is sent so the server validates it against its menu BEFORE adding
	// the peer; an unknown name is then rejected with no peer created. By the
	// time we get OK back, chooseEndpoint below cannot fail.
	req := protocol.Request{
		Op:           protocol.OpAdd,
		Name:         opts.Name,
		PublicKey:    wgkey.Encode(pub),
		PresharedKey: psk,
		Endpoint:     opts.Endpoint,
	}
	out, err := c.call(protocol.OpAdd, req)
	if err != nil {
		return "", resp, err
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", resp, fmt.Errorf("decoding add response: %w", err)
	}
	if !resp.OK {
		return "", resp, responseError(resp.Status)
	}

	endpoint, err := chooseEndpoint(resp.Endpoints, opts.Endpoint)
	if err != nil {
		// Should not happen: the server validated the endpoint before creating
		// the peer.
		return "", resp, err
	}
	configText = assembleConfig(wgkey.Encode(priv), psk, endpoint, opts.Split, resp)
	return configText, resp, nil
}

// List returns the server's file-derived peer list (spec §6).
func (c *Client) List() (protocol.ListResponse, error) {
	var resp protocol.ListResponse
	out, err := c.call(protocol.OpList, protocol.Request{Op: protocol.OpList})
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, fmt.Errorf("decoding list response: %w", err)
	}
	if !resp.OK {
		return resp, responseError(resp.Status)
	}
	return resp, nil
}

// Kill removes a peer by name (spec §6).
func (c *Client) Kill(name string) (protocol.KillResponse, error) {
	var resp protocol.KillResponse
	out, err := c.call(protocol.OpKill, protocol.Request{Op: protocol.OpKill, Name: name})
	if err != nil {
		return resp, err
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return resp, fmt.Errorf("decoding kill response: %w", err)
	}
	if !resp.OK {
		return resp, responseError(resp.Status)
	}
	return resp, nil
}

func (c *Client) call(op string, req protocol.Request) ([]byte, error) {
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return c.Exec(op, reqJSON)
}

// chooseEndpoint resolves the --endpoint flag against the server menu, falling
// back to the first (default) entry (spec §6).
func chooseEndpoint(menu []protocol.Endpoint, name string) (protocol.Endpoint, error) {
	if len(menu) == 0 {
		return protocol.Endpoint{}, fmt.Errorf("server returned no endpoints")
	}
	if name == "" {
		return menu[0], nil
	}
	for _, e := range menu {
		if e.Name == name {
			return e, nil
		}
	}
	var names []string
	for _, e := range menu {
		names = append(names, e.Name)
	}
	return protocol.Endpoint{}, fmt.Errorf("unknown endpoint %q (available: %s)", name, strings.Join(names, ", "))
}

// assembleConfig builds the final client wg config. The private key is supplied
// by the caller and never leaves the machine (spec §9).
func assembleConfig(privB64, psk string, endpoint protocol.Endpoint, split bool, r protocol.AddResponse) string {
	allowed := r.AllowedIPs
	if split {
		if r.Subnet != "" {
			allowed = []string{r.Subnet}
		} else {
			allowed = r.AllowedIPs // server too old to advertise subnet; keep full
		}
	}

	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privB64)
	fmt.Fprintf(&b, "Address = %s\n", r.IP)
	if len(r.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(r.DNS, ", "))
	}
	if r.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", r.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", r.ServerPublicKey)
	if psk != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint.Addr)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	if r.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", r.PersistentKeepalive)
	}
	return b.String()
}

// responseError turns a failed Status into a Go error carrying the code.
func responseError(s protocol.Status) error {
	if s.Message != "" {
		return fmt.Errorf("server error [%s]: %s", s.Error, s.Message)
	}
	return fmt.Errorf("server error [%s]", s.Error)
}
