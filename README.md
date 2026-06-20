# wgpeer

A small Go CLI to manage WireGuard peers. From a phone (termux → ssh) you add a
named key and get a QR; later you list peers or kill one. **The wg `.conf` is the
source of truth**; the opinionated server `[Interface]` (PreUp/PostUp, `ip rule`,
non-standard MTU) is preserved verbatim and never regenerated.

See [`wireguard-peer-cli-spec.md`](wireguard-peer-cli-spec.md) for the full design.

## How it works

One binary, two modes (a shared `protocol` package keeps them in lockstep):

- `wgpeer server --iface <wgN> <add|list|kill>` — the privileged half, run under
  `ssh` + `sudo` on the server. Headless: reads a JSON request on stdin, writes a
  JSON response on stdout, exit code is the status. It edits
  `/etc/wireguard/<iface>.conf` under an `flock`, writes atomically
  (temp → fsync → rename), and applies the delta with `wg syncconf` (no device
  bounce, no hooks).
- `wgpeer client <add|list|kill>` — the unprivileged half, on termux/laptop. It
  generates the private key **locally** (it never leaves the machine), drives the
  server over ssh, assembles the client config, and draws the QR.

`ssh` is the only authorization boundary — there is no daemon, UI, or token.

## Install

```sh
go build -o wgpeer .                 # native
# cross-compile (pure Go, no cgo):
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o wgpeer-linux-amd64 .
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -o wgpeer-android-arm64 .   # termux
```

Server side:

1. Put the binary at e.g. `/usr/local/bin/wgpeer`.
2. Create a per-interface config: `/etc/wgpeer/wg0.toml`
   (see [`examples/wg0.toml`](examples/wg0.toml)). No file for an interface ⇒
   wgpeer refuses to operate on it.
3. Scope sudo to `wgpeer server` (see [`examples/wgpeer.sudoers`](examples/wgpeer.sudoers)).
4. The interface's `[Interface]` must contain `PrivateKey` — the server derives
   and advertises its own public key from it.

Client side: create `~/.config/wgpeer/client.toml`
(see [`examples/client.toml`](examples/client.toml)).

## Usage

```sh
# add a peer, print the config and a terminal QR
wgpeer client add "Вася's phone"
wgpeer client add bob --iface wg1 --endpoint tspu-443
wgpeer client add laptop --split            # route only the server subnet
wgpeer client add tablet --no-psk           # no preshared key
wgpeer client add kiosk --qr-png kiosk.png  # write a PNG instead of a terminal QR
wgpeer client add phone --invert            # flip QR colours for a light terminal

wgpeer client list
wgpeer client list --json
wgpeer client kill bob
```

The peer **name is a label, not an identity** — the real identity is the public
key. `kill` resolves a name to its key; adding a duplicate name fails with
`name_taken`.

## Configuration

| File | Format | Purpose |
|------|--------|---------|
| `/etc/wireguard/<iface>.conf` | INI (wg) | source of truth for peers |
| `/etc/wgpeer/<iface>.toml` | TOML | server defaults + pointer to the .conf |
| `~/.config/wgpeer/client.toml` | TOML | client menu of servers × interfaces |
| client↔server over ssh | JSON | ephemeral wire protocol |

`WGPEER_CONFIG_DIR` overrides the server config directory (default `/etc/wgpeer`).

## Errors

A non-zero exit carries a JSON `{"ok":false,"error":...}` with one of:
`name_taken`, `no_free_ip`, `not_found`, `locked`, `bad_request`, `internal`.

## Tests

```sh
go test ./...                              # unit tests (parser, allocator, client flow)
sudo go test -tags integration ./internal/server/   # real wg syncconf on a disposable interface
```
