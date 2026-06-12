package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config holds all arx-dns runtime settings loaded from a TOML file.
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Zones     ZonesConfig     `toml:"zones"`
	Recursive RecursiveConfig `toml:"recursive"`
	Firewall  FirewallConfig  `toml:"firewall"`
}

// ServerConfig controls the DNS listener bind address and reactor sizing.
type ServerConfig struct {
	Listen     string `toml:"listen"`
	Port       int    `toml:"port"`
	EventLoops int    `toml:"event_loops"`
}

// ZonesConfig controls authoritative zone file storage.
type ZonesConfig struct {
	Directory string `toml:"directory"`
}

// RecursiveConfig controls upstream forwarding and client ACL prefixes.
type RecursiveConfig struct {
	Upstreams      []string `toml:"upstreams"`
	TrustedSubnets []string `toml:"trusted_subnets"`
}

// FirewallConfig controls DNS blocklist loading and block actions.
type FirewallConfig struct {
	BlocklistsDirectory string `toml:"blocklists_directory"`
	BlockAction         string `toml:"block_action"`
}

const (
	defaultListen            = "0.0.0.0"
	defaultPort              = 53
	defaultZonesDir          = "./zones"
	defaultBlocklistsDir     = "./blocklists"
	defaultBlockAction       = "NXDOMAIN"
	defaultUpstreamPrimary   = "1.1.1.1:53"
	defaultUpstreamSecondary = "1.0.0.1:53"
)

// Default returns a Config populated with the same defaults as the legacy CLI flags.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:     defaultListen,
			Port:       defaultPort,
			EventLoops: 0,
		},
		Zones: ZonesConfig{
			Directory: defaultZonesDir,
		},
		Recursive: RecursiveConfig{
			Upstreams: []string{
				defaultUpstreamPrimary,
				defaultUpstreamSecondary,
			},
			TrustedSubnets: []string{
				"127.0.0.0/8",
				"10.0.0.0/8",
				"192.168.0.0/16",
			},
		},
		Firewall: FirewallConfig{
			BlocklistsDirectory: defaultBlocklistsDir,
			BlockAction:         defaultBlockAction,
		},
	}
}

// Load reads the TOML file at path. When the file does not exist, a default
// configuration file is written to path and the default values are returned.
func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("config path must not be empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		cfg := Default()
		if err := Write(path, cfg); err != nil {
			return Config{}, fmt.Errorf("create default config %q: %w", path, err)
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg := Default()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config %q: %w", path, err)
	}

	return cfg, nil
}

// Write encodes cfg as TOML and writes it to path, creating parent directories when needed.
func Write(path string, cfg Config) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}

	data, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

func (c *Config) applyDefaults() {
	def := Default()

	if strings.TrimSpace(c.Server.Listen) == "" {
		c.Server.Listen = def.Server.Listen
	}
	if c.Server.Port == 0 {
		c.Server.Port = def.Server.Port
	}
	if strings.TrimSpace(c.Zones.Directory) == "" {
		c.Zones.Directory = def.Zones.Directory
	}
	if len(c.Recursive.Upstreams) == 0 {
		c.Recursive.Upstreams = append([]string(nil), def.Recursive.Upstreams...)
	}
	if len(c.Recursive.TrustedSubnets) == 0 {
		c.Recursive.TrustedSubnets = append([]string(nil), def.Recursive.TrustedSubnets...)
	}
	if strings.TrimSpace(c.Firewall.BlocklistsDirectory) == "" {
		c.Firewall.BlocklistsDirectory = def.Firewall.BlocklistsDirectory
	}
	if strings.TrimSpace(c.Firewall.BlockAction) == "" {
		c.Firewall.BlockAction = def.Firewall.BlockAction
	}
}

// Validate checks that all configuration fields are usable at runtime.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Server.Listen) == "" {
		return errors.New("server.listen must not be empty")
	}
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}
	if strings.TrimSpace(c.Zones.Directory) == "" {
		return errors.New("zones.directory must not be empty")
	}
	if strings.TrimSpace(c.Firewall.BlocklistsDirectory) == "" {
		return errors.New("firewall.blocklists_directory must not be empty")
	}
	if err := validateBlockAction(c.Firewall.BlockAction); err != nil {
		return err
	}
	if _, err := c.TrustedSubnetsCSV(); err != nil {
		return err
	}
	if _, err := c.NormalizedUpstreams(); err != nil {
		return err
	}

	return nil
}

// ListenAddress returns the server bind address in host:port form.
func (c Config) ListenAddress() string {
	return net.JoinHostPort(c.Server.Listen, strconv.Itoa(c.Server.Port))
}

// TrustedSubnetsCSV joins trusted subnet prefixes for ACL parsing.
func (c Config) TrustedSubnetsCSV() (string, error) {
	parts := make([]string, 0, len(c.Recursive.TrustedSubnets))
	for _, subnet := range c.Recursive.TrustedSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		parts = append(parts, subnet)
	}
	return strings.Join(parts, ","), nil
}

// NormalizedUpstreams returns upstream resolver addresses in host:port form.
func (c Config) NormalizedUpstreams() ([]string, error) {
	out := make([]string, 0, len(c.Recursive.Upstreams))

	for _, part := range c.Recursive.Upstreams {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		host, port, err := net.SplitHostPort(part)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				part = net.JoinHostPort(part, "53")
			} else {
				return nil, fmt.Errorf("invalid upstream %q: %w", part, err)
			}
		} else if host == "" || port == "" {
			return nil, fmt.Errorf("invalid upstream address %q", part)
		}

		out = append(out, part)
	}

	if len(out) == 0 {
		return nil, errors.New("at least one upstream DNS server is required")
	}

	return out, nil
}

func validateBlockAction(raw string) error {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case defaultBlockAction, "ZEROIP", "":
		return nil
	default:
		return fmt.Errorf("unknown firewall block action %q (expected NXDOMAIN or ZEROIP)", raw)
	}
}
