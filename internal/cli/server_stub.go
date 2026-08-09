//go:build !linux || clientonly

package cli

import (
	"fmt"
	"os"
)

// This file is the client-only build: the exact complement of server.go's
// `linux && !clientonly`. It stands in for the privileged half so the rest of
// the CLI — and the binary — need not know whether that half was compiled in.
//
// Two ways to get here:
//
//   - a non-Linux target (macOS, Windows, *BSD), where the server half cannot
//     work anyway: it drives wg-quick, systemctl and /etc/wireguard, and does
//     not even compile on Windows (no syscall.Flock);
//   - -tags clientonly on Linux, to leave the privileged code out of a binary
//     that will only ever be a client. Termux needs this one: GOOS=android
//     satisfies the `linux` build tag, so an android build is NOT client-only
//     by default.
//
// Nothing is lost either way — the client half reaches a real Linux server
// over ssh, which is the normal way to run wgpeer regardless.

// serverUsage replaces the server-mode section of the help text with a note
// that this build has no such mode.
func serverUsage() string {
	return `
  wgpeer server …
      Not in this build: wgpeer was built client-only, without the privileged
      half (that half is Linux-only). Run it on the WireGuard server itself;
      this binary drives it from here over ssh.
`
}

// serverMain refuses server mode with the same explanation, rather than
// pretending the subcommand does not exist — the user typed something valid,
// just not for this binary.
func serverMain(args []string) int {
	fmt.Fprintln(os.Stderr, "wgpeer: this is a client-only build — it has no server half.")
	fmt.Fprintln(os.Stderr, "The privileged half is Linux-only (it drives wg-quick, systemctl and /etc/wireguard);")
	fmt.Fprintln(os.Stderr, "run `wgpeer server …` on the WireGuard server itself. From here, use `wgpeer client …`,")
	fmt.Fprintln(os.Stderr, "which does exactly that over ssh.")
	return 2
}
