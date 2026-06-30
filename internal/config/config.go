package config

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	Server    ServerConfig    `toml:"server" json:"server"`
	TLS       TLSConfig       `toml:"tls" json:"tls"`
	Listeners ListenersConfig `toml:"listeners" json:"listeners"`
	API       APIConfig       `toml:"api" json:"api"`
	Zones     ZonesConfig     `toml:"zones" json:"zones"`
	Recursive RecursiveConfig `toml:"recursive" json:"recursive"`
	Resolver  ResolverConfig  `toml:"resolver" json:"resolver"`
	Firewall  FirewallConfig  `toml:"firewall" json:"firewall"`
	Security  SecurityConfig  `toml:"security" json:"security"`
	RateLimit RateLimitConfig `toml:"rate_limit" json:"rate_limit"`
	ECS       ECSConfig       `toml:"ecs" json:"ecs"`
	Logging   LoggingConfig   `toml:"logging" json:"logging"`
	Update    UpdateConfig    `toml:"update" json:"update"`
	XFR       XFRConfig       `toml:"xfr" json:"xfr"`
	ACL       ACLConfig       `toml:"acl" json:"acl"`
	Views     ViewsConfig     `toml:"views" json:"views"`
}

// LoggingConfig controls structured log file rotation parameters.
type LoggingConfig struct {
	FilePath   string `toml:"file_path" json:"file_path"`
	MaxSizeMB  int    `toml:"max_size_mb" json:"max_size_mb"`
	MaxBackups int    `toml:"max_backups" json:"max_backups"`
	MaxAgeDays int    `toml:"max_age_days" json:"max_age_days"`
}

// XFRConfig controls zone transfer (AXFR/IXFR) ACLs and NOTIFY slave targets.
type XFRConfig struct {
	Enabled        bool     `toml:"enabled" json:"enabled"`
	AllowedSubnets []string `toml:"allowed_subnets" json:"allowed_subnets"`
	NotifySlaves   []string `toml:"notify_slaves" json:"notify_slaves"`
}

// UpdateConfig controls RFC 2136 dynamic DNS updates secured with TSIG.
type UpdateConfig struct {
	// Keys maps TSIG key names (canonical FQDN, e.g. "update-key.") to base64-encoded secrets.
	Keys map[string]string `toml:"keys" json:"keys"`
}

// ECSConfig controls EDNS Client Subnet (RFC 7871) forwarding to upstream resolvers.
type ECSConfig struct {
	Enabled          bool `toml:"enabled" json:"enabled"`
	IPv4PrefixLength int  `toml:"ipv4_prefix_length" json:"ipv4_prefix_length"`
	IPv6PrefixLength int  `toml:"ipv6_prefix_length" json:"ipv6_prefix_length"`
}

// RateLimitConfig controls per-client-IP response rate limiting (RRL).
type RateLimitConfig struct {
	Enabled           bool `toml:"enabled" json:"enabled"`
	RequestsPerSecond int  `toml:"requests_per_second" json:"requests_per_second"`
	Burst             int  `toml:"burst" json:"burst"`
}

// SecurityConfig controls DNSSEC, DNS Cookies, and related validation policies.
type SecurityConfig struct {
	DNSSECValidation  bool     `toml:"dnssec_validation" json:"dnssec_validation"`
	DNSCookiesEnabled bool     `toml:"dns_cookies_enabled" json:"dns_cookies_enabled"`
	DNSCookieSecret   string   `toml:"dns_cookie_secret" json:"dns_cookie_secret,omitempty"`
	RootAnchors       []string `toml:"root_anchors" json:"root_anchors"`
}

// ServerConfig controls the DNS listener bind address and reactor sizing.
type ServerConfig struct {
	Listen     string `toml:"listen" json:"listen"`
	Port       int    `toml:"port" json:"port"`
	EventLoops int    `toml:"event_loops" json:"event_loops"`
	LogLevel   string `toml:"log_level" json:"log_level"`
}

// TLSConfig holds the server certificate and private key for encrypted DNS transports.
type TLSConfig struct {
	CertFile string `toml:"cert_file" json:"cert_file"`
	KeyFile  string `toml:"key_file" json:"key_file"`
}

// ListenersConfig controls bind addresses for DNS-over-TLS and DNS-over-HTTPS.
type ListenersConfig struct {
	DoT string `toml:"dot" json:"dot"`
	DoH string `toml:"doh" json:"doh"`
}

// APIConfig controls the management and telemetry HTTP API listener.
type APIConfig struct {
	Listen    string `toml:"listen" json:"listen"`
	AuthToken string `toml:"auth_token" json:"auth_token"`
	TLSCert   string `toml:"tls_cert" json:"tls_cert"`
	TLSKey    string `toml:"tls_key" json:"tls_key"`
}

// ZonesConfig controls authoritative zone file storage.
type ZonesConfig struct {
	Directory string `toml:"directory" json:"directory"`
}

// RecursiveConfig controls upstream forwarding and client ACL prefixes.
type RecursiveConfig struct {
	Upstreams      []string `toml:"upstreams" json:"upstreams"`
	TrustedSubnets []string `toml:"trusted_subnets" json:"trusted_subnets"`
}

// ResolverConfig selects recursive resolution strategy (forward vs iterative).
type ResolverConfig struct {
	Mode                string `toml:"mode" json:"mode"`
	QNameMinimization   bool   `toml:"qname_minimization" json:"qname_minimization"`
	RootHintsFile       string `toml:"root_hints_file" json:"root_hints_file"`
	AutoUpdateRootHints bool   `toml:"auto_update_root_hints" json:"auto_update_root_hints"`
}

// FirewallConfig controls DNS blocklist loading and block actions.
type FirewallConfig struct {
	BlocklistsDirectory string `toml:"blocklists_directory" json:"blocklists_directory"`
	BlockAction         string `toml:"block_action" json:"block_action"`
}

const (
	defaultListen            = "0.0.0.0"
	defaultPort              = 53
	defaultDoTListen         = ":853"
	defaultDoHListen         = ":443"
	defaultZonesDir          = "./zones"
	defaultBlocklistsDir     = "./blocklists"
	defaultBlockAction       = "NXDOMAIN"
	defaultUpstreamPrimary   = "1.1.1.1"
	defaultUpstreamSecondary = "1.0.0.1"
	defaultAPIListen         = "127.0.0.1:8080"
	defaultAPIAuthToken      = "dev-token-change-me"
	defaultRateLimitRPS      = 100
	defaultRateLimitBurst    = 200
	defaultECSIPv4PrefixLen  = 24
	defaultECSIPv6PrefixLen  = 56
	defaultResolverMode      = "forward"
	defaultLogLevel          = "INFO"
	defaultRootHintsFile     = "./data/named.root"
	defaultLogFilePath       = "./logs/arx-dns.log"
	defaultLogMaxSizeMB      = 50
	defaultLogMaxBackups     = 3
	defaultLogMaxAgeDays     = 28
)

// DefaultRootHints returns the 13 standard IPv4 root server addresses (RFC root hint set).
func DefaultRootHints() []string {
	return []string{
		"198.41.0.4",
		"199.9.14.201",
		"192.33.4.12",
		"199.7.91.13",
		"192.203.230.10",
		"192.5.5.241",
		"192.32.92.29",
		"216.146.53.2",
		"192.36.134.14",
		"192.58.128.30",
		"193.0.14.129",
		"199.7.83.42",
		"202.12.27.33",
	}
}

// Default returns a Config populated with the same defaults as the legacy CLI flags.
func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:     defaultListen,
			Port:       defaultPort,
			EventLoops: 0,
			LogLevel:   defaultLogLevel,
		},
		Listeners: ListenersConfig{
			DoT: defaultDoTListen,
			DoH: defaultDoHListen,
		},
		API: APIConfig{
			Listen:    defaultAPIListen,
			AuthToken: defaultAPIAuthToken,
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
		Resolver: ResolverConfig{
			Mode:                defaultResolverMode,
			QNameMinimization:   true,
			RootHintsFile:       defaultRootHintsFile,
			AutoUpdateRootHints: true,
		},
		Firewall: FirewallConfig{
			BlocklistsDirectory: defaultBlocklistsDir,
			BlockAction:         defaultBlockAction,
		},
		Security: SecurityConfig{
			DNSSECValidation:  true,
			DNSCookiesEnabled: true,
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: defaultRateLimitRPS,
			Burst:             defaultRateLimitBurst,
		},
		ECS: ECSConfig{
			Enabled:          false,
			IPv4PrefixLength: defaultECSIPv4PrefixLen,
			IPv6PrefixLength: defaultECSIPv6PrefixLen,
		},
		Logging: LoggingConfig{
			FilePath:   defaultLogFilePath,
			MaxSizeMB:  defaultLogMaxSizeMB,
			MaxBackups: defaultLogMaxBackups,
			MaxAgeDays: defaultLogMaxAgeDays,
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
		if err := writeDefaultConfig(path); err != nil {
			return Config{}, fmt.Errorf("create default config %q: %w", path, err)
		}
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
	cfg.normalizeUpdateKeys()
	if err := cfg.EnsureDNSCookieSecret(path); err != nil {
		return Config{}, fmt.Errorf("ensure dns cookie secret: %w", err)
	}
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
	if strings.TrimSpace(c.Server.LogLevel) == "" {
		c.Server.LogLevel = def.Server.LogLevel
	}
	if strings.TrimSpace(c.Resolver.RootHintsFile) == "" {
		c.Resolver.RootHintsFile = def.Resolver.RootHintsFile
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
	if strings.TrimSpace(c.Listeners.DoT) == "" {
		c.Listeners.DoT = def.Listeners.DoT
	}
	if strings.TrimSpace(c.Listeners.DoH) == "" {
		c.Listeners.DoH = def.Listeners.DoH
	}
	if strings.TrimSpace(c.API.Listen) == "" {
		c.API.Listen = def.API.Listen
	}
	if strings.TrimSpace(c.API.AuthToken) == "" {
		c.API.AuthToken = def.API.AuthToken
	}
	if c.RateLimit.RequestsPerSecond == 0 {
		c.RateLimit.RequestsPerSecond = def.RateLimit.RequestsPerSecond
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = def.RateLimit.Burst
	}
	if c.ECS.IPv4PrefixLength == 0 {
		c.ECS.IPv4PrefixLength = def.ECS.IPv4PrefixLength
	}
	if c.ECS.IPv6PrefixLength == 0 {
		c.ECS.IPv6PrefixLength = def.ECS.IPv6PrefixLength
	}
	if strings.TrimSpace(c.Resolver.Mode) == "" {
		c.Resolver.Mode = def.Resolver.Mode
	}
	if strings.TrimSpace(c.Logging.FilePath) == "" {
		c.Logging = def.Logging
	} else if c.Logging.MaxSizeMB == 0 {
		c.Logging.MaxSizeMB = def.Logging.MaxSizeMB
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
	if err := validateLogLevel(c.Server.LogLevel); err != nil {
		return err
	}
	if strings.TrimSpace(c.Resolver.RootHintsFile) == "" {
		return errors.New("resolver.root_hints_file must not be empty")
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
	if err := c.validateResolver(); err != nil {
		return err
	}
	if err := c.validateTLS(); err != nil {
		return err
	}
	if err := c.validateAPI(); err != nil {
		return err
	}
	if err := c.validateRateLimit(); err != nil {
		return err
	}
	if err := c.validateSecurity(); err != nil {
		return err
	}
	if err := c.validateECS(); err != nil {
		return err
	}
	if err := c.validateUpdate(); err != nil {
		return err
	}
	if err := c.validateXFR(); err != nil {
		return err
	}
	if err := c.validateACL(); err != nil {
		return err
	}
	if err := c.validateLogging(); err != nil {
		return err
	}

	return nil
}

func (c Config) validateLogging() error {
	if strings.TrimSpace(c.Logging.FilePath) == "" {
		return errors.New("logging.file_path must not be empty")
	}
	if c.Logging.MaxSizeMB <= 0 {
		return errors.New("logging.max_size_mb must be greater than zero")
	}
	if c.Logging.MaxBackups < 0 {
		return errors.New("logging.max_backups must be zero or greater")
	}
	if c.Logging.MaxAgeDays < 0 {
		return errors.New("logging.max_age_days must be zero or greater")
	}
	return nil
}

// RequiresRestart reports whether applying next would need a process restart
// because listener bind addresses or encrypted transport certificates changed.
func RequiresRestart(current, next Config) bool {
	if current.Server.Listen != next.Server.Listen ||
		current.Server.Port != next.Server.Port ||
		current.Server.EventLoops != next.Server.EventLoops {
		return true
	}
	if current.Listeners.DoT != next.Listeners.DoT ||
		current.Listeners.DoH != next.Listeners.DoH {
		return true
	}
	if current.API.Listen != next.API.Listen ||
		current.API.TLSCert != next.API.TLSCert ||
		current.API.TLSKey != next.API.TLSKey {
		return true
	}
	if current.TLS.CertFile != next.TLS.CertFile ||
		current.TLS.KeyFile != next.TLS.KeyFile {
		return true
	}
	if current.ResolverMode() != next.ResolverMode() {
		return true
	}
	return false
}

// MergeWithCurrent overlays an API update onto the active configuration while
// preserving infrastructure and secret fields when the payload omits them.
func MergeWithCurrent(current, incoming Config) Config {
	out := incoming

	if strings.TrimSpace(out.Server.Listen) == "" {
		out.Server.Listen = current.Server.Listen
	}
	if out.Server.Port == 0 {
		out.Server.Port = current.Server.Port
	}

	if strings.TrimSpace(out.TLS.CertFile) == "" && strings.TrimSpace(out.TLS.KeyFile) == "" {
		out.TLS = current.TLS
	}

	if strings.TrimSpace(out.Listeners.DoT) == "" {
		out.Listeners.DoT = current.Listeners.DoT
	}
	if strings.TrimSpace(out.Listeners.DoH) == "" {
		out.Listeners.DoH = current.Listeners.DoH
	}

	if strings.TrimSpace(out.API.Listen) == "" {
		out.API.Listen = current.API.Listen
	}
	if strings.TrimSpace(out.API.AuthToken) == "" {
		out.API.AuthToken = current.API.AuthToken
	}
	if strings.TrimSpace(out.API.TLSCert) == "" && strings.TrimSpace(out.API.TLSKey) == "" {
		out.API.TLSCert = current.API.TLSCert
		out.API.TLSKey = current.API.TLSKey
	}

	if strings.TrimSpace(out.Zones.Directory) == "" {
		out.Zones.Directory = current.Zones.Directory
	}

	if strings.TrimSpace(out.Firewall.BlocklistsDirectory) == "" {
		out.Firewall.BlocklistsDirectory = current.Firewall.BlocklistsDirectory
	}
	if strings.TrimSpace(out.Firewall.BlockAction) == "" {
		out.Firewall.BlockAction = current.Firewall.BlockAction
	}

	if len(out.Recursive.Upstreams) == 0 {
		out.Recursive.Upstreams = append([]string(nil), current.Recursive.Upstreams...)
	}
	if len(out.Recursive.TrustedSubnets) == 0 {
		out.Recursive.TrustedSubnets = append([]string(nil), current.Recursive.TrustedSubnets...)
	}

	if strings.TrimSpace(out.Resolver.RootHintsFile) == "" {
		out.Resolver.RootHintsFile = current.Resolver.RootHintsFile
	}

	if strings.TrimSpace(out.Security.DNSCookieSecret) == "" {
		out.Security.DNSCookieSecret = current.Security.DNSCookieSecret
	}

	if out.Update.Keys == nil {
		out.Update.Keys = current.Update.Keys
	}

	if !out.XFR.Enabled && len(out.XFR.AllowedSubnets) == 0 && len(out.XFR.NotifySlaves) == 0 {
		out.XFR = current.XFR
	}

	if out.ACL.Lists == nil && len(out.ACL.AllowQuery) == 0 && len(out.ACL.AllowRecursion) == 0 &&
		len(out.ACL.AllowTransfer) == 0 && len(out.ACL.Zones) == 0 {
		out.ACL = current.ACL
	}
	if out.Views.Default == "" && len(out.Views.Entries) == 0 {
		out.Views = current.Views
	}

	return out
}

// PrepareForApply normalizes and validates an incoming configuration payload.
func PrepareForApply(in Config) (Config, error) {
	in.applyDefaults()
	in.normalizeUpdateKeys()
	if err := in.Validate(); err != nil {
		return Config{}, err
	}
	if err := in.normalizeUpstreamsForStorage(); err != nil {
		return Config{}, err
	}
	return in, nil
}

func (c *Config) normalizeUpstreamsForStorage() error {
	if c.ResolverMode() != "forward" {
		return nil
	}
	normalized, err := c.ValidatedUpstreams()
	if err != nil {
		return err
	}
	c.Recursive.Upstreams = normalized
	return nil
}

func (c *Config) normalizeUpdateKeys() {
	if c.Update.Keys == nil {
		c.Update.Keys = make(map[string]string)
		return
	}
	normalized := make(map[string]string, len(c.Update.Keys))
	for name, secret := range c.Update.Keys {
		name = normalizeTSIGKeyName(name)
		if name == "" {
			continue
		}
		normalized[name] = strings.TrimSpace(secret)
	}
	c.Update.Keys = normalized
}

func normalizeTSIGKeyName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return ""
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func (c Config) validateUpdate() error {
	for name, secret := range c.Update.Keys {
		if secret == "" {
			return fmt.Errorf("update.keys[%q] must not be empty", name)
		}
		if _, err := decodeBase64Secret(secret); err != nil {
			return fmt.Errorf("update.keys[%q]: %w", name, err)
		}
	}
	return nil
}

func decodeBase64Secret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil, errors.New("empty secret")
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 secret: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("decoded secret is empty")
	}
	return raw, nil
}

// NormalizedTSIGKeys returns TSIG key names mapped to base64 secrets in canonical form.
func (c Config) NormalizedTSIGKeys() map[string]string {
	out := make(map[string]string, len(c.Update.Keys))
	for name, secret := range c.Update.Keys {
		name = normalizeTSIGKeyName(name)
		if name == "" {
			continue
		}
		out[name] = strings.TrimSpace(secret)
	}
	return out
}

func (c Config) validateECS() error {
	if c.ECS.IPv4PrefixLength < 0 || c.ECS.IPv4PrefixLength > 32 {
		return fmt.Errorf("ecs.ipv4_prefix_length must be between 0 and 32, got %d", c.ECS.IPv4PrefixLength)
	}
	if c.ECS.IPv6PrefixLength < 0 || c.ECS.IPv6PrefixLength > 128 {
		return fmt.Errorf("ecs.ipv6_prefix_length must be between 0 and 128, got %d", c.ECS.IPv6PrefixLength)
	}
	return nil
}

// EnsureDNSCookieSecret generates and persists a random 32-byte hex secret when DNS
// Cookies are enabled and dns_cookie_secret is empty.
func (c *Config) EnsureDNSCookieSecret(path string) error {
	if !c.Security.DNSCookiesEnabled {
		return nil
	}
	if strings.TrimSpace(c.Security.DNSCookieSecret) != "" {
		return nil
	}

	secret, err := generateDNSCookieSecret()
	if err != nil {
		return err
	}
	c.Security.DNSCookieSecret = secret

	if path == "" {
		return nil
	}
	return Write(path, *c)
}

// DNSCookieSecretBytes decodes the configured hex secret into a 32-byte slice.
func (c Config) DNSCookieSecretBytes() ([]byte, error) {
	secret := strings.TrimSpace(c.Security.DNSCookieSecret)
	if secret == "" {
		return nil, errors.New("dns_cookie_secret is empty")
	}
	raw, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("decode dns_cookie_secret: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("dns_cookie_secret must decode to 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

func (c Config) validateSecurity() error {
	if err := c.Security.ValidateRootAnchors(); err != nil {
		return err
	}
	if !c.Security.DNSCookiesEnabled {
		return nil
	}
	secret := strings.TrimSpace(c.Security.DNSCookieSecret)
	if secret == "" {
		return errors.New("security.dns_cookie_secret must be set when dns_cookies_enabled is true")
	}
	if len(secret) != 64 {
		return errors.New("security.dns_cookie_secret must be a 64-character hex string (32 bytes)")
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return fmt.Errorf("security.dns_cookie_secret: %w", err)
	}
	return nil
}

func generateDNSCookieSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate dns cookie secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (c Config) validateRateLimit() error {
	if !c.RateLimit.Enabled {
		return nil
	}
	if c.RateLimit.RequestsPerSecond < 1 {
		return errors.New("rate_limit.requests_per_second must be at least 1 when rate limiting is enabled")
	}
	if c.RateLimit.Burst < 1 {
		return errors.New("rate_limit.burst must be at least 1 when rate limiting is enabled")
	}
	return nil
}

func (c Config) validateAPI() error {
	if strings.TrimSpace(c.API.Listen) == "" {
		return errors.New("api.listen must not be empty")
	}
	if _, err := net.ResolveTCPAddr("tcp", c.API.Listen); err != nil {
		return fmt.Errorf("api.listen %q: %w", c.API.Listen, err)
	}
	if strings.TrimSpace(c.API.AuthToken) == "" {
		return errors.New("api.auth_token must not be empty")
	}
	return c.validateAPITLS()
}

func (c Config) validateAPITLS() error {
	cert := strings.TrimSpace(c.API.TLSCert)
	key := strings.TrimSpace(c.API.TLSKey)

	if cert == "" && key == "" {
		return nil
	}
	if cert == "" {
		return errors.New("api.tls_cert is required when api.tls_key is set")
	}
	if key == "" {
		return errors.New("api.tls_key is required when api.tls_cert is set")
	}

	if _, err := os.Stat(cert); err != nil {
		return fmt.Errorf("api.tls_cert %q: %w", cert, err)
	}
	if _, err := os.Stat(key); err != nil {
		return fmt.Errorf("api.tls_key %q: %w", key, err)
	}

	return nil
}

// APITLSEnabled reports whether TLS certificate paths are configured for the management API.
func (c Config) APITLSEnabled() bool {
	return strings.TrimSpace(c.API.TLSCert) != "" && strings.TrimSpace(c.API.TLSKey) != ""
}

func (c Config) validateTLS() error {
	cert := strings.TrimSpace(c.TLS.CertFile)
	key := strings.TrimSpace(c.TLS.KeyFile)

	if cert == "" && key == "" {
		return nil
	}
	if cert == "" {
		return errors.New("tls.cert_file is required when tls.key_file is set")
	}
	if key == "" {
		return errors.New("tls.key_file is required when tls.cert_file is set")
	}

	if _, err := os.Stat(cert); err != nil {
		return fmt.Errorf("tls.cert_file %q: %w", cert, err)
	}
	if _, err := os.Stat(key); err != nil {
		return fmt.Errorf("tls.key_file %q: %w", key, err)
	}

	return nil
}

// EncryptedDNSEnabled reports whether TLS certificate paths are configured.
func (c Config) EncryptedDNSEnabled() bool {
	return strings.TrimSpace(c.TLS.CertFile) != "" && strings.TrimSpace(c.TLS.KeyFile) != ""
}

// BuildTLSConfig loads the configured certificate pair for encrypted DNS listeners.
func (c Config) BuildTLSConfig() (*tls.Config, error) {
	if !c.EncryptedDNSEnabled() {
		return nil, errors.New("tls certificate and key paths are required")
	}

	cert, err := tls.LoadX509KeyPair(c.TLS.CertFile, c.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls certificate: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, nil
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

// ResolverMode returns the normalized resolver mode ("forward" or "iterative").
func (c Config) ResolverMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.Resolver.Mode))
	if mode == "" {
		return defaultResolverMode
	}
	return mode
}

func (c Config) validateResolver() error {
	switch c.ResolverMode() {
	case "forward":
		if _, err := c.ValidatedUpstreams(); err != nil {
			return err
		}
	case "iterative":
		// Root hints are loaded dynamically at runtime from resolver.root_hints_file.
	default:
		return fmt.Errorf("resolver.mode must be forward or iterative, got %q", c.Resolver.Mode)
	}
	return nil
}

// NormalizedUpstreams returns upstream resolver addresses in host:port form for dialing.
func (c Config) NormalizedUpstreams() ([]string, error) {
	validated, err := c.ValidatedUpstreams()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(validated))
	for i, addr := range validated {
		out[i] = DialUpstreamAddress(addr)
	}
	return out, nil
}

// ForAPIResponse returns a copy of cfg with upstream ports normalized for UI display.
func (c Config) ForAPIResponse() Config {
	out := c
	out.Recursive.Upstreams = DisplayUpstreams(c.Recursive.Upstreams)
	return out
}

func (c Config) validateXFR() error {
	if !c.XFR.Enabled {
		return nil
	}
	if _, err := c.XFRAllowedSubnetsCSV(); err != nil {
		return err
	}
	if _, err := c.NormalizedNotifySlaves(); err != nil {
		return err
	}
	return nil
}

// XFRAllowedSubnetsCSV joins zone-transfer ACL prefixes for parsing.
func (c Config) XFRAllowedSubnetsCSV() (string, error) {
	parts := make([]string, 0, len(c.XFR.AllowedSubnets))
	for _, subnet := range c.XFR.AllowedSubnets {
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		parts = append(parts, subnet)
	}
	return strings.Join(parts, ","), nil
}

// NormalizedNotifySlaves returns slave addresses in host:port form (default port 53).
func (c Config) NormalizedNotifySlaves() ([]string, error) {
	out := make([]string, 0, len(c.XFR.NotifySlaves))
	for _, raw := range c.XFR.NotifySlaves {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		addr, err := normalizeNotifySlave(raw)
		if err != nil {
			return nil, fmt.Errorf("xfr.notify_slaves %q: %w", raw, err)
		}
		out = append(out, addr)
	}
	return out, nil
}

func normalizeNotifySlave(raw string) (string, error) {
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if host == "" || port == "" {
			return "", fmt.Errorf("invalid address")
		}
		return net.JoinHostPort(host, port), nil
	}
	if strings.Contains(raw, ":") {
		return net.JoinHostPort(raw, "53"), nil
	}
	return net.JoinHostPort(raw, "53"), nil
}

func validateLogLevel(raw string) error {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG", "INFO", "WARN", "WARNING", "ERROR":
		return nil
	default:
		return fmt.Errorf("server.log_level must be DEBUG, INFO, WARN, or ERROR, got %q", raw)
	}
}

func validateBlockAction(raw string) error {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case defaultBlockAction, "ZEROIP", "":
		return nil
	default:
		return fmt.Errorf("unknown firewall block action %q (expected NXDOMAIN or ZEROIP)", raw)
	}
}
