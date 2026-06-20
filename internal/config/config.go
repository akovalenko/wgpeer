// Package config loads the TOML configuration for both halves of wgpeer
// (spec §4): the per-interface server config /etc/wgpeer/<iface>.toml and the
// client menu ~/.config/wgpeer/client.toml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/pelletier/go-toml/v2"

	"github.com/akovalenko/wgpeer/internal/protocol"
)

// DefaultServerDir is where per-interface server configs live (spec §4.1).
// Overridable via WGPEER_CONFIG_DIR (used by tests and unusual layouts).
const DefaultServerDir = "/etc/wgpeer"

// Template holds the server-owned defaults for the client config (spec §4.1).
type Template struct {
	DNS                 []string `toml:"dns"`
	AllowedIPs          []string `toml:"allowed_ips"`
	PersistentKeepalive int      `toml:"persistent_keepalive"`
	MTU                 int      `toml:"mtu"`
	PSKDefault          bool     `toml:"psk_default"`
}

// ServerConfig is /etc/wgpeer/<iface>.toml. The interface name is implied by
// the filename, not stored in the file (spec §4.1).
type ServerConfig struct {
	Iface     string              `toml:"-"`
	ConfPath  string              `toml:"conf_path"`
	Subnet    string              `toml:"subnet"`
	Reserved  []string            `toml:"reserved"`
	Template  Template            `toml:"template"`
	Endpoints []protocol.Endpoint `toml:"endpoint"`
}

// ServerDir returns the directory holding per-interface server configs.
func ServerDir() string {
	if d := os.Getenv("WGPEER_CONFIG_DIR"); d != "" {
		return d
	}
	return DefaultServerDir
}

// LoadServer reads /etc/wgpeer/<iface>.toml. A missing file is a refusal to
// operate on that interface (spec §2, §4.1) — guards against accidentally
// seizing somebody else's wg.
func LoadServer(iface string) (*ServerConfig, error) {
	if iface == "" {
		return nil, errors.New("empty interface name")
	}
	path := filepath.Join(ServerDir(), iface+".toml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no config for interface %q (%s): refusing to operate", iface, path)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg ServerConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg.Iface = iface
	if cfg.ConfPath == "" {
		return nil, fmt.Errorf("%s: conf_path is required", path)
	}
	if cfg.Subnet == "" {
		return nil, fmt.Errorf("%s: subnet is required", path)
	}
	return &cfg, nil
}

// ServerEntry is one [[server]] in the client menu (spec §4.2).
type ServerEntry struct {
	Name   string   `toml:"name"`
	SSH    string   `toml:"ssh"`
	Sudo   bool     `toml:"sudo"`
	Ifaces []string `toml:"ifaces"`
}

// ClientConfig is ~/.config/wgpeer/client.toml — the menu of servers and their
// interfaces (spec §4.2).
type ClientConfig struct {
	DefaultServer string        `toml:"default_server"`
	Servers       []ServerEntry `toml:"server"`
}

// ClientPath returns the path to the client config, honouring XDG_CONFIG_HOME.
func ClientPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "wgpeer", "client.toml"), nil
}

// LoadClient reads ~/.config/wgpeer/client.toml.
func LoadClient() (*ClientConfig, error) {
	path, err := ClientPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg ClientConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

// Resolve picks the server entry and interface for a client command given the
// optional --server / --iface flags, applying the spec §4.2 defaults
// (default_server, then ifaces[0]).
func (c *ClientConfig) Resolve(server, iface string) (*ServerEntry, string, error) {
	if len(c.Servers) == 0 {
		return nil, "", errors.New("no servers configured")
	}
	if server == "" {
		server = c.DefaultServer
	}
	var entry *ServerEntry
	if server == "" {
		entry = &c.Servers[0]
	} else {
		for i := range c.Servers {
			if c.Servers[i].Name == server {
				entry = &c.Servers[i]
				break
			}
		}
		if entry == nil {
			return nil, "", fmt.Errorf("unknown server %q", server)
		}
	}
	if iface == "" {
		if len(entry.Ifaces) == 0 {
			return nil, "", fmt.Errorf("server %q has no interfaces configured", entry.Name)
		}
		iface = entry.Ifaces[0]
	} else if len(entry.Ifaces) > 0 && !slices.Contains(entry.Ifaces, iface) {
		return nil, "", fmt.Errorf("server %q has no interface %q", entry.Name, iface)
	}
	return entry, iface, nil
}
