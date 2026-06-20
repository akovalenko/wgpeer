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
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// Client drives one server interface. Exec runs `wgpeer server …` remotely,
// sending the request JSON on stdin and returning its stdout; it is a field so
// tests can substitute an in-process server.
type Client struct {
	SSHTarget string
	Sudo      bool
	Iface     string
	Exec      func(op string, reqJSON []byte) (stdout []byte, err error)
}

// NewSSH builds a Client whose Exec shells out to the system ssh (honouring
// ~/.ssh/config, agent, aliases — spec §14).
func NewSSH(sshTarget string, sudo bool, iface string) *Client {
	c := &Client{SSHTarget: sshTarget, Sudo: sudo, Iface: iface}
	c.Exec = c.sshExec
	return c
}

func (c *Client) sshExec(op string, reqJSON []byte) ([]byte, error) {
	remote := []string{}
	if c.Sudo {
		remote = append(remote, "sudo")
	}
	remote = append(remote, "wgpeer", "server", "--iface", c.Iface, op)
	cmd := exec.Command("ssh", append([]string{c.SSHTarget}, remote...)...)
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

	req := protocol.Request{
		Op:           protocol.OpAdd,
		Name:         opts.Name,
		PublicKey:    wgkey.Encode(pub),
		PresharedKey: psk,
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
