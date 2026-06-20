// Package wgconf is the heart of wgpeer: a small, tolerant reader/writer for a
// WireGuard .conf where the file is the source of truth for peers (spec §7).
//
// Invariants:
//   - The [Interface] section — and any unrecognised content before the first
//     [Peer] — is preserved VERBATIM. That block is opinionated (PreUp/PostUp,
//     ip rule, non-standard MTU) and must never be regenerated (spec §1, §7).
//   - [Peer] blocks are owned by the tool and re-emitted in a fixed canonical
//     form: lead comments, an optional "# name:" comment, then [Peer], then
//     PublicKey, PresharedKey (only when set), AllowedIPs, then body comments.
//     Old peer blocks are normalised: their values and comments are kept, their
//     formatting is canonicalised.
//   - Comments that are not in "# name:" form are preserved in place: comments
//     directly above a [Peer] become LeadComments; comments inside the block
//     become BodyComments (spec §7, plus Anton's 2026-06-20 addendum).
//
// Together this makes Serialize idempotent (a canonical file round-trips
// byte-for-byte) while keeping the parser tolerant of reasonable old layouts.
package wgconf

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// Peer is one [Peer] block. Identity is PublicKey; Name is a human label only
// (spec §5). Recognised fields are normalised on rewrite; unknown keys (e.g.
// Endpoint) are dropped by design, but comments are kept (spec §7).
type Peer struct {
	LeadComments []string // verbatim non-name comments directly above [Peer]
	Name         string   // from "# name:"; "" if none
	PublicKey    string
	PresharedKey string // "" when the peer has no PSK
	AllowedIPs   []netip.Prefix
	BodyComments []string // verbatim comments that appeared inside the block
}

// Conf is a parsed wg .conf: a verbatim header plus owned peer blocks.
type Conf struct {
	Header string // everything before the first peer block, kept verbatim
	Peers  []Peer
}

// Parse reads a wg .conf. It never fails on tolerable formatting; it only errors
// on content it cannot make sense of (e.g. a malformed AllowedIPs value).
func Parse(data []byte) (*Conf, error) {
	text := string(data)
	lines, offsets := splitLines(text)

	var peerIdx []int
	for i, l := range lines {
		if isPeerHeader(l) {
			peerIdx = append(peerIdx, i)
		}
	}
	if len(peerIdx) == 0 {
		return &Conf{Header: text}, nil
	}

	// Header boundary: everything before the first [Peer], minus an immediately
	// preceding "# name:" line (which belongs to that peer). Other comments
	// above the first peer stay in the verbatim header to honour "[Interface]
	// verbatim" — we never reach into it.
	peerStart := peerIdx[0]
	if peerIdx[0] > 0 {
		if _, ok := nameComment(lines[peerIdx[0]-1]); ok {
			peerStart = peerIdx[0] - 1
		}
	}
	c := &Conf{Header: text[:offsets[peerStart]]}

	for k, p := range peerIdx {
		var peer Peer

		// Lead = the run of comment lines directly above [Peer] (stopping at a
		// blank or non-comment line). The first peer's lead is bounded by the
		// header so we never pull comments out of [Interface].
		ls := peerStart
		if k > 0 {
			ls = leadStart(lines, p, peerIdx[k-1]+1)
		}
		for _, raw := range lines[ls:p] {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			if name, ok := nameComment(raw); ok {
				peer.Name = name
			} else {
				peer.LeadComments = append(peer.LeadComments, strings.TrimSpace(raw))
			}
		}

		// Body = lines after [Peer] up to the next peer's lead (or EOF).
		bodyEnd := len(lines)
		if k+1 < len(peerIdx) {
			bodyEnd = leadStart(lines, peerIdx[k+1], p+1)
		}
		for _, raw := range lines[p+1 : bodyEnd] {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "#") {
				// Includes any name-form comment that appears inside the body:
				// preserved verbatim rather than reinterpreted as a name.
				peer.BodyComments = append(peer.BodyComments, trimmed)
				continue
			}
			key, val, found := strings.Cut(raw, "=")
			if !found {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			switch strings.ToLower(key) {
			case "publickey":
				peer.PublicKey = val
			case "presharedkey":
				peer.PresharedKey = val
			case "allowedips":
				for part := range strings.SplitSeq(val, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					pfx, err := parsePrefix(part)
					if err != nil {
						return nil, fmt.Errorf("peer %q: %w", peer.Name, err)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, pfx)
				}
			default:
				// Unknown key (e.g. Endpoint): dropped on rewrite (spec §7).
			}
		}
		c.Peers = append(c.Peers, peer)
	}
	return c, nil
}

// Serialize renders the conf back to bytes: the verbatim header followed by
// canonical peer blocks, one blank line apart.
func (c *Conf) Serialize() []byte {
	var b strings.Builder
	header := strings.TrimRight(c.Header, "\n")
	b.WriteString(header)
	if header != "" {
		b.WriteString("\n")
	}
	for _, p := range c.Peers {
		b.WriteString("\n")
		for _, lc := range p.LeadComments {
			b.WriteString(lc)
			b.WriteString("\n")
		}
		if p.Name != "" {
			b.WriteString("# name: ")
			b.WriteString(p.Name)
			b.WriteString("\n")
		}
		b.WriteString("[Peer]\n")
		b.WriteString("PublicKey = ")
		b.WriteString(p.PublicKey)
		b.WriteString("\n")
		if p.PresharedKey != "" {
			b.WriteString("PresharedKey = ")
			b.WriteString(p.PresharedKey)
			b.WriteString("\n")
		}
		ips := make([]string, len(p.AllowedIPs))
		for i, a := range p.AllowedIPs {
			ips[i] = a.String()
		}
		b.WriteString("AllowedIPs = ")
		b.WriteString(strings.Join(ips, ", "))
		b.WriteString("\n")
		for _, bc := range p.BodyComments {
			b.WriteString(bc)
			b.WriteString("\n")
		}
	}
	return []byte(b.String())
}

// FindByName returns the index of the peer with the given name, or -1.
func (c *Conf) FindByName(name string) int {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return i
		}
	}
	return -1
}

// NameExists reports whether a peer with the given non-empty name exists.
func (c *Conf) NameExists(name string) bool {
	return name != "" && c.FindByName(name) >= 0
}

// ValidPeerName checks that a name can be written as a single-line "# name:"
// comment without corrupting the conf. The critical case is a newline, which
// would otherwise let a name inject extra [Peer] blocks; all control characters
// are rejected for good measure. Leading/trailing whitespace is rejected so the
// stored name round-trips exactly (the parser trims it). Unicode letters and
// internal spaces (e.g. "для Васи") are fine.
func ValidPeerName(name string) error {
	if name == "" {
		return fmt.Errorf("name is empty")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("name must not contain control characters (newlines, tabs, etc.)")
		}
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("name must not have leading or trailing whitespace")
	}
	return nil
}

// AddPeer appends a peer block.
func (c *Conf) AddPeer(p Peer) {
	c.Peers = append(c.Peers, p)
}

// RemoveByName removes the first peer matching name and returns it.
func (c *Conf) RemoveByName(name string) (Peer, bool) {
	i := c.FindByName(name)
	if i < 0 {
		return Peer{}, false
	}
	removed := c.Peers[i]
	c.Peers = append(c.Peers[:i], c.Peers[i+1:]...)
	return removed, true
}

// InterfacePrivateKey extracts PrivateKey from the verbatim [Interface] header,
// so the server can derive and advertise its own public key without shelling
// out to wg. Returns "" if absent.
func (c *Conf) InterfacePrivateKey() string {
	for raw := range strings.SplitSeq(c.Header, "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, val, found := strings.Cut(raw, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "privatekey") {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

// leadStart walks back from a [Peer] line over the contiguous run of comment
// lines directly above it, stopping at a blank line, a non-comment line, or the
// lower bound. The returned index is the first line of that lead run.
func leadStart(lines []string, peer, lower int) int {
	s := peer
	for s-1 >= lower {
		prev := strings.TrimSpace(lines[s-1])
		if prev == "" || !strings.HasPrefix(prev, "#") {
			break
		}
		s--
	}
	return s
}

// splitLines splits text into lines (without their trailing newline) and the
// byte offset at which each line begins, so the header can be sliced verbatim.
func splitLines(text string) (lines []string, offsets []int) {
	i := 0
	for {
		j := strings.IndexByte(text[i:], '\n')
		if j < 0 {
			lines = append(lines, text[i:])
			offsets = append(offsets, i)
			return
		}
		lines = append(lines, text[i:i+j])
		offsets = append(offsets, i)
		i += j + 1
	}
}

func isPeerHeader(line string) bool {
	return strings.EqualFold(strings.TrimSpace(line), "[Peer]")
}

// nameComment recognises a "# name: <value>" line and returns the value.
func nameComment(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "#") {
		return "", false
	}
	t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
	rest, ok := strings.CutPrefix(t, "name:")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

// parsePrefix parses an AllowedIPs entry, accepting both "10.0.0.7/32" and a
// bare "10.0.0.7" (treated as a /32 host).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("bad AllowedIPs %q: %w", s, err)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad AllowedIPs %q: %w", s, err)
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(a, bits), nil
}
