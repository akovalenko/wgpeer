package wgconf

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ErrNoFreeIP is returned by AllocateIP when the subnet is exhausted (spec §7).
var ErrNoFreeIP = errors.New("no free IP in subnet")

// AllocateIP returns the next free host address in subnet, treating as occupied
// every AllowedIPs host across all peers plus the reserved set (spec §7).
// v1 is v4-only (spec §12). The returned address is a /32.
//
// The network and broadcast addresses are skipped for prefixes shorter than
// /31 (conventional, avoids handing out .0/.255 on a /24).
func (c *Conf) AllocateIP(subnet netip.Prefix, reserved []netip.Addr) (netip.Prefix, error) {
	subnet = subnet.Masked()
	occupied := make(map[netip.Addr]bool)
	for _, r := range reserved {
		occupied[r] = true
	}
	for i := range c.Peers {
		for _, a := range c.Peers[i].AllowedIPs {
			occupied[a.Addr()] = true // host part
		}
	}

	first := subnet.Addr()
	last := lastAddr(subnet)
	cur, end := first, last
	if subnet.Bits() < 31 {
		cur = first.Next() // skip network address
		end = last.Prev()  // skip broadcast address
	}
	for ; cur.Compare(end) <= 0; cur = cur.Next() {
		if !occupied[cur] {
			return netip.PrefixFrom(cur, cur.BitLen()), nil
		}
	}
	return netip.Prefix{}, ErrNoFreeIP
}

// lastAddr returns the highest address contained in a v4 prefix (its broadcast
// address): the network address with all host bits set.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := binary.BigEndian.Uint32(b[:])
	hostBits := uint(32 - p.Bits())
	if hostBits >= 32 {
		v = ^uint32(0)
	} else {
		v |= (uint32(1) << hostBits) - 1
	}
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}
