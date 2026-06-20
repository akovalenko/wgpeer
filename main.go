// Command wgpeer is a small CLI to manage WireGuard peers: from a phone over
// ssh, add a named key (and get a QR), list them, or kill one. The wg .conf is
// the source of truth; the opinionated server [Interface] is never regenerated.
//
// See wireguard-peer-cli-spec.md for the design.
package main

import (
	"os"

	"github.com/akovalenko/wgpeer/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
