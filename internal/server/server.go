// Package server implements the privileged half of wgpeer (spec §2): it owns
// /etc/wireguard/<iface>.conf, mutates peer blocks under an flock with atomic
// writes, and applies the delta with `wg syncconf`. It runs headless behind
// ssh+sudo and speaks the JSON protocol.
package server

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/akovalenko/wgpeer/internal/config"
	"github.com/akovalenko/wgpeer/internal/protocol"
	"github.com/akovalenko/wgpeer/internal/wgconf"
	"github.com/akovalenko/wgpeer/internal/wgkey"
)

// DefaultLockTimeout bounds how long add/kill wait for the flock (spec §11).
const DefaultLockTimeout = 5 * time.Second

// Server handles operations against one interface's conf.
type Server struct {
	Cfg         *config.ServerConfig
	LockTimeout time.Duration
	// Apply pushes the on-disk conf to the live interface. Overridable in tests
	// so the mutation logic can run without a real wg device.
	Apply func(iface, confPath string) error
}

// New builds a Server with production defaults.
func New(cfg *config.ServerConfig) *Server {
	return &Server{
		Cfg:         cfg,
		LockTimeout: DefaultLockTimeout,
		Apply:       applySyncconf,
	}
}

// Add registers a new peer: validate, lock, allocate an IP, append a canonical
// [Peer] block, persist atomically, and sync the live interface (spec §2, §6).
func (s *Server) Add(req protocol.Request) protocol.AddResponse {
	if req.Name == "" || req.PublicKey == "" {
		return protocol.AddResponse{Status: badRequest("name and public_key are required")}
	}
	if _, err := wgkey.Decode(req.PublicKey); err != nil {
		return protocol.AddResponse{Status: badRequest("public_key: " + err.Error())}
	}
	if req.PresharedKey != "" {
		if _, err := wgkey.Decode(req.PresharedKey); err != nil {
			return protocol.AddResponse{Status: badRequest("preshared_key: " + err.Error())}
		}
	}
	subnet, reserved, errResp := s.network()
	if errResp != nil {
		return protocol.AddResponse{Status: *errResp}
	}

	lock, err := acquireLock(s.Cfg.ConfPath, s.lockTimeout())
	if err != nil {
		return protocol.AddResponse{Status: lockOrInternal(err)}
	}
	defer releaseLock(lock)

	conf, errResp := s.read()
	if errResp != nil {
		return protocol.AddResponse{Status: *errResp}
	}
	if conf.NameExists(req.Name) {
		return protocol.AddResponse{Status: status(protocol.ErrNameTaken, fmt.Sprintf("name %q already exists", req.Name))}
	}
	ip, err := conf.AllocateIP(subnet, reserved)
	if err != nil {
		return protocol.AddResponse{Status: status(protocol.ErrNoFreeIP, err.Error())}
	}
	conf.AddPeer(wgconf.Peer{
		Name:         req.Name,
		PublicKey:    req.PublicKey,
		PresharedKey: req.PresharedKey,
		AllowedIPs:   []netip.Prefix{ip},
	})
	if errResp := s.commit(conf); errResp != nil {
		return protocol.AddResponse{Status: *errResp}
	}

	serverPub, err := wgkey.PublicFromPrivateBase64(conf.InterfacePrivateKey())
	if err != nil {
		return protocol.AddResponse{Status: internal("deriving server public key: " + err.Error())}
	}
	t := s.Cfg.Template
	return protocol.AddResponse{
		Status:              protocol.Status{OK: true},
		IP:                  ip.String(),
		ServerPublicKey:     serverPub,
		Endpoints:           s.Cfg.Endpoints,
		DNS:                 t.DNS,
		AllowedIPs:          t.AllowedIPs,
		PersistentKeepalive: t.PersistentKeepalive,
		MTU:                 t.MTU,
		Subnet:              s.Cfg.Subnet,
	}
}

// List reports peers straight from the conf file (v1: no `wg show`, spec §6).
// No lock needed: atomic rename means a reader sees a complete file.
func (s *Server) List() protocol.ListResponse {
	conf, errResp := s.read()
	if errResp != nil {
		return protocol.ListResponse{Status: *errResp}
	}
	peers := make([]protocol.PeerInfo, 0, len(conf.Peers))
	for _, p := range conf.Peers {
		ip := ""
		if len(p.AllowedIPs) > 0 {
			ip = p.AllowedIPs[0].String()
		}
		peers = append(peers, protocol.PeerInfo{
			Name:      p.Name,
			PublicKey: p.PublicKey,
			IP:        ip,
			PSK:       p.PresharedKey != "",
		})
	}
	return protocol.ListResponse{Status: protocol.Status{OK: true}, Peers: peers}
}

// Kill removes a peer by name and syncs the interface (spec §6).
func (s *Server) Kill(req protocol.Request) protocol.KillResponse {
	if req.Name == "" {
		return protocol.KillResponse{Status: badRequest("name is required")}
	}
	lock, err := acquireLock(s.Cfg.ConfPath, s.lockTimeout())
	if err != nil {
		return protocol.KillResponse{Status: lockOrInternal(err)}
	}
	defer releaseLock(lock)

	conf, errResp := s.read()
	if errResp != nil {
		return protocol.KillResponse{Status: *errResp}
	}
	removed, ok := conf.RemoveByName(req.Name)
	if !ok {
		return protocol.KillResponse{Status: status(protocol.ErrNotFound, fmt.Sprintf("no peer named %q", req.Name))}
	}
	if errResp := s.commit(conf); errResp != nil {
		return protocol.KillResponse{Status: *errResp}
	}
	return protocol.KillResponse{
		Status:  protocol.Status{OK: true},
		Removed: &protocol.RemovedPeer{Name: removed.Name, PublicKey: removed.PublicKey},
	}
}

// read loads and parses the conf file.
func (s *Server) read() (*wgconf.Conf, *protocol.Status) {
	data, err := os.ReadFile(s.Cfg.ConfPath)
	if err != nil {
		st := internal("reading " + s.Cfg.ConfPath + ": " + err.Error())
		return nil, &st
	}
	conf, err := wgconf.Parse(data)
	if err != nil {
		st := internal("parsing " + s.Cfg.ConfPath + ": " + err.Error())
		return nil, &st
	}
	return conf, nil
}

// commit persists the conf atomically (0600) and applies the delta to wg.
func (s *Server) commit(conf *wgconf.Conf) *protocol.Status {
	if err := atomicWrite(s.Cfg.ConfPath, conf.Serialize(), 0600); err != nil {
		st := internal("writing " + s.Cfg.ConfPath + ": " + err.Error())
		return &st
	}
	if s.Apply != nil {
		if err := s.Apply(s.Cfg.Iface, s.Cfg.ConfPath); err != nil {
			st := internal("applying config (file updated): " + err.Error())
			return &st
		}
	}
	return nil
}

// network parses the subnet and reserved addresses from config.
func (s *Server) network() (netip.Prefix, []netip.Addr, *protocol.Status) {
	subnet, err := netip.ParsePrefix(s.Cfg.Subnet)
	if err != nil {
		st := internal("bad subnet in config: " + err.Error())
		return netip.Prefix{}, nil, &st
	}
	var reserved []netip.Addr
	for _, r := range s.Cfg.Reserved {
		a, err := netip.ParseAddr(r)
		if err != nil {
			st := internal("bad reserved address in config: " + err.Error())
			return netip.Prefix{}, nil, &st
		}
		reserved = append(reserved, a)
	}
	return subnet, reserved, nil
}

func (s *Server) lockTimeout() time.Duration {
	if s.LockTimeout <= 0 {
		return DefaultLockTimeout
	}
	return s.LockTimeout
}

func status(code, msg string) protocol.Status {
	return protocol.Status{OK: false, Error: code, Message: msg}
}

func badRequest(msg string) protocol.Status { return status(protocol.ErrBadRequest, msg) }
func internal(msg string) protocol.Status   { return status(protocol.ErrInternal, msg) }

func lockOrInternal(err error) protocol.Status {
	if err == errLocked {
		return status(protocol.ErrLocked, err.Error())
	}
	return internal(err.Error())
}
