// Package protocol defines the JSON request/response types exchanged between
// the wgpeer client and server halves over a single ssh-exec. It compiles into
// both modes so the wire format can never drift between them (spec §2, §5).
package protocol

// Operation codes carried in Request.Op and echoed by the server subcommand.
const (
	OpAdd     = "add"
	OpList    = "list"
	OpKill    = "kill"
	OpProvide = "provide"
)

// Error codes (spec §5, §11). Returned in Status.Error on failure.
const (
	ErrNameTaken  = "name_taken"
	ErrNoFreeIP   = "no_free_ip"
	ErrNotFound   = "not_found"
	ErrLocked     = "locked"
	ErrBadRequest = "bad_request"
	ErrInternal   = "internal"
)

// Request is the single request envelope sent on stdin (client → server).
//
//	{ "op":"add", "name":"для Васи", "public_key":"<base64>",
//	  "preshared_key":"<base64|null>", "endpoint":"public" }
//
// Endpoint is the requested endpoint menu name. The client still owns the
// choice, but it is sent so the server can validate it against its menu BEFORE
// mutating — an unknown name must fail without ever creating a peer. "" selects
// the default (first menu entry). It is a deliberate, backward-compatible
// addition over the spec's AddRequest sketch (spec §5, §9).
type Request struct {
	Op           string `json:"op"`
	Name         string `json:"name,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"` // "" / null = no PSK
	Endpoint     string `json:"endpoint,omitempty"`      // "" = default (menu[0])
}

// Endpoint is one entry of the server's vantage-dependent endpoint menu.
type Endpoint struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// PeerInfo is one row of a list response (file-derived in v1, spec §5).
type PeerInfo struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`
	PSK       bool   `json:"psk"`
}

// RemovedPeer identifies the peer a kill removed.
type RemovedPeer struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// Status is the common envelope embedded in every response. On error the
// server writes only these fields ({ok:false, error, message}), which still
// decodes cleanly into any typed response with OK=false.
type Status struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// AddResponse is returned for OpAdd (spec §5). The client assembles the final
// peer config locally from these server-owned fields plus its private key.
//
// Subnet is a deliberate, backward-compatible addition over the spec sketch so
// the client's --split (split-tunnel) override has a route to install (spec §9
// names split/full as a client-owned override but the sketch omits the field).
type AddResponse struct {
	Status
	IP                  string     `json:"ip,omitempty"`
	ServerPublicKey     string     `json:"server_public_key,omitempty"`
	Endpoints           []Endpoint `json:"endpoints,omitempty"`
	DNS                 []string   `json:"dns,omitempty"`
	AllowedIPs          []string   `json:"allowed_ips,omitempty"`
	PersistentKeepalive int        `json:"persistent_keepalive,omitempty"`
	MTU                 int        `json:"mtu,omitempty"`
	Subnet              string     `json:"subnet,omitempty"`
}

// ListResponse is returned for OpList (spec §5).
type ListResponse struct {
	Status
	Peers []PeerInfo `json:"peers,omitempty"`
}

// KillResponse is returned for OpKill (spec §5).
type KillResponse struct {
	Status
	Removed *RemovedPeer `json:"removed,omitempty"`
}

// ProvideResponse is returned for OpProvide: it bootstraps a brand-new interface
// (fresh [Interface] + sidecar) rather than mutating peers. The fields report
// what was invented so a future `client provide` wrapper — or a human reading the
// stderr summary — can see the generated address, port, key, and endpoint menu.
type ProvideResponse struct {
	Status
	Iface               string     `json:"iface,omitempty"`
	ConfPath            string     `json:"conf_path,omitempty"`
	SidecarPath         string     `json:"sidecar_path,omitempty"`
	Subnet              string     `json:"subnet,omitempty"`
	Address             string     `json:"address,omitempty"` // server address with prefix, e.g. 172.19.0.1/16
	ListenPort          int        `json:"listen_port,omitempty"`
	ServerPublicKey     string     `json:"server_public_key,omitempty"`
	Endpoints           []Endpoint `json:"endpoints,omitempty"`
	AllowedIPs          []string   `json:"allowed_ips,omitempty"`          // pushed to clients (full-tunnel default)
	DNS                 []string   `json:"dns,omitempty"`                  // pushed to clients; empty = unset
	MTU                 int        `json:"mtu,omitempty"`                  // pushed to clients; 0 = unset
	PersistentKeepalive int        `json:"persistent_keepalive,omitempty"` // pushed to clients; 0 = unset
	Enabled             bool       `json:"enabled"`                        // systemctl enable --now wg-quick@<iface> ran
}
