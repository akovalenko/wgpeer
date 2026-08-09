# wgpeer

A small Go CLI to manage WireGuard peers. From a phone (termux → ssh) you add a
named key and get a QR; later you list peers or kill one. **The wg `.conf` is the
source of truth**; the opinionated server `[Interface]` (PreUp/PostUp, `ip rule`,
non-standard MTU) is preserved verbatim and never regenerated.

See [`wireguard-peer-cli-spec.md`](wireguard-peer-cli-spec.md) for the full design.

## How it works

One binary, two modes (a shared `protocol` package keeps them in lockstep) — or
just the client half, where that is all that can run (see
[Client-only builds](#client-only-builds)):

- `wgpeer server --iface <wgN> <add|list|kill|rename>` — the privileged half, run
  under `ssh` + `sudo` on the server. Headless: reads a JSON request on stdin,
  writes a JSON response on stdout, exit code is the status. It edits
  `/etc/wireguard/<iface>.conf` under an `flock`, writes atomically
  (temp → fsync → rename), and applies the delta with `wg syncconf` (no device
  bounce, no hooks).
- `wgpeer client <add|list|kill|rename>` — the unprivileged half, on termux/laptop.
  It generates the private key **locally** (it never leaves the machine), drives
  the server over ssh, assembles the client config, and draws the QR.

The word `client` is optional — `wgpeer add bob` is `wgpeer client add bob`. The
client half is the one typed daily, so it is what a bare subcommand means; the
server half always spells out `wgpeer server …`.

Two server-side subcommands manage a whole interface rather than its peers:

- `wgpeer server provide <wgN> …` / `wgpeer server remove <wgN>` — bootstrap or
  tear down an interface: generate (or delete) the `.conf` + sidecar and enable
  (or disable) `wg-quick`. Flag-driven admin commands run on the server; a human
  summary goes to stderr and a JSON response to stdout.

`ssh` is the only authorization boundary — there is no daemon, UI, or token.

## Install

```sh
go build -o wgpeer .                 # native
# cross-compile (pure Go, no cgo):
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o wgpeer-linux-amd64 .
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -tags clientonly -o wgpeer-android-arm64 .   # termux
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o wgpeer-darwin-arm64 .    # client-only
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o wgpeer-windows-amd64.exe .
```

### Client-only builds

The server half is Linux-only — not by accident of a syscall, but because every
path it drives is one: `wg-quick`, `systemctl`, `/etc/wireguard`. So on any
non-Linux target it is simply left out, automatically:

| Target | What you get |
|--------|--------------|
| Linux | both halves (default) |
| Linux + `-tags clientonly` | client only |
| Android/termux | both halves — **unless** `-tags clientonly` (see below) |
| macOS, Windows, \*BSD | client only, automatically |

The client half is unchanged in such a build — it does what it always does,
driving a real Linux server over ssh. Only the local privileged code is absent,
and `wgpeer server …` says so instead of failing obscurely. It is also a little
smaller, which is the other reason to ask for it on Linux.

Note the termux row: Go's `android` target satisfies the `linux` build
constraint, so an android build carries the server half unless you say
`-tags clientonly`. On a phone you want the tag — the privileged code has
nothing to drive there.

Server side:

1. Put the binary at e.g. `/usr/local/bin/wgpeer`.
2. Create a per-interface config: `/etc/wgpeer/wg0.toml`
   (see [`examples/wg0.toml`](examples/wg0.toml)). No file for an interface ⇒
   wgpeer refuses to operate on it. Or let `wgpeer server provide` (below)
   generate both the `.conf` and this sidecar for you.
3. Scope sudo to `wgpeer server` (see [`examples/wgpeer.sudoers`](examples/wgpeer.sudoers)).
4. The interface's `[Interface]` must contain `PrivateKey` — the server derives
   and advertises its own public key from it.

Client side: create `~/.config/wgpeer/client.toml`
(see [`examples/client.toml`](examples/client.toml)).

## Usage

```sh
# add a peer: config to stdout, terminal QR to stderr (when stdout is a TTY)
wgpeer client add "Вася's phone"
wgpeer client add bob --iface wg1 --endpoint tspu-443
wgpeer client add laptop --split             # route only the server subnet
wgpeer client add tablet --no-psk            # no preshared key
wgpeer client add kiosk --qr-png kiosk.png   # also write a PNG
wgpeer client add phone --invert             # flip QR colours for a light terminal

# piping/redirecting gives just the config — the QR is on stderr, not in the file:
wgpeer client add work > work.conf && nmcli connection import type wireguard file work.conf
wgpeer client add work --qr never > work.conf   # suppress the QR entirely

wgpeer client list
wgpeer client list --json
wgpeer client kill bob
wgpeer client rename bob "Боб на новом телефоне"   # relabel; the key stays put

# "client" is optional — these are the same commands:
wgpeer add bob
wgpeer list
wgpeer kill bob
```

The config is written to **stdout** and the terminal QR to **stderr**, so
redirecting stdout yields a clean config file with the QR still shown on the
terminal. Use `--qr never` to suppress the QR; `--qr-png FILE` writes a PNG
independently of the terminal QR.

The peer **name is a label, not an identity** — the real identity is the public
key. `kill` resolves a name to its key; adding a duplicate name fails with
`name_taken`. Names must be a single line (no control characters) and carry no
leading/trailing whitespace.

Because it is only a label, `rename` is cheap: it moves the `# name:` comment and
nothing else, so the peer keeps its key, PSK and address and any config already
handed out keeps working (no re-issue, no new QR). It takes exactly two names —
quote any that contain spaces — refuses a name already in use (`name_taken`,
the same uniqueness `add` enforces, since the label is what `kill`/`rename`
resolve on), and skips `wg syncconf`: the kernel never sees the comment, so
there is nothing to push.

## Provisioning an interface (server side)

Rather than hand-writing the sidecar and the wg `.conf`, bootstrap both with
`provide`; the inverse, `remove`, tears them down. Both run **on the server**
(under `sudo`), are flag-driven (no stdin JSON), and print a human summary on
stderr with a JSON response on stdout.

```sh
# create wg0: pick the peer pool, autodetect the public endpoint, bring it up
sudo wgpeer server provide wg0 --net 172.19.0.0/16

sudo wgpeer server provide wg0 --net 10.8.0.0/24 --endpoint vpn.example.com:51820
sudo wgpeer server provide wg0 --net 172.19.0.0/16 --allowed-ips subnet  # split-tunnel
sudo wgpeer server provide wg0 --net 172.19.0.0/16 --dns 1.1.1.1 --keepalive 25
sudo wgpeer server provide wg0 --net 172.19.0.0/16 --no-up                # write files only
```

`provide` generates the server keypair, writes `/etc/wireguard/<iface>.conf`
(0600) and the `/etc/wgpeer/<iface>.toml` sidecar, then — unless `--no-up` —
runs `systemctl enable --now wg-quick@<iface>`. It refuses to touch an interface
whose conf or sidecar already exists. Defaults: a random high `ListenPort`, the
first host of `--net` as the server address, the public IPv4(s) autodetected as
the endpoint menu, full-tunnel `AllowedIPs`, and DNS/MTU/keepalive left unset
(`--allowed-ips subnet` gives split-tunnel to `--net` only).

```sh
# tear wg0 back down: stop & disable wg-quick, delete conf + sidecar
sudo wgpeer server remove wg0
sudo wgpeer server remove wg0 --yes         # skip the confirmation prompt
sudo wgpeer server remove wg0 --no-backup   # do not keep a .conf backup
```

`remove` is interactive: it prints exactly what it will destroy and reads a y/N
confirmation (a non-terminal stdin without `--yes` is refused rather than acted
on blindly). Because the server private key lives **only** in the `.conf`, the
conf is copied to `<conf>.bak-YYYYMMDD` (0600) before deletion — `--no-backup`
opts out. Stopping/disabling `wg-quick` and the deletes are best-effort: a unit
already down or a file already gone is noted, not fatal, so a partial prior
teardown still converges.

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
go test -tags clientonly ./...             # same, minus the server half
GOOS=darwin go vet ./... && GOOS=windows go vet ./...   # client-only builds still compile
sudo go test -tags integration ./internal/server/   # real wg syncconf on a disposable interface
```

Tests that need the server half (the in-process client↔server suite, the
`confirmRemove` prompt) live in files carrying the same build tag as the code
they exercise, so `./...` stays green on every target.
