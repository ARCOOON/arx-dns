package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultConfigTemplate is the embedded TOML written on first startup when no config file exists.
const defaultConfigTemplate = `# arx-dns default configuration (auto-generated on first startup)

[server]
listen = '0.0.0.0'
port = 53
event_loops = 0
log_level = 'INFO'

[zones]
directory = './zones'

[recursive]
upstreams = ['1.1.1.1:53', '1.0.0.1:53']
trusted_subnets = ['127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16']

[resolver]
mode = 'forward'
qname_minimization = true
root_hints_file = './data/named.root'
auto_update_root_hints = true

[firewall]
blocklists_directory = './blocklists'
block_action = 'NXDOMAIN'

[security]
dnssec_validation = true
dns_cookies_enabled = true
dns_cookie_secret = ''

[rate_limit]
enabled = true
requests_per_second = 100
burst = 200

[logging]
file_path = './logs/arx-dns.log'
max_size_mb = 50
max_backups = 3
max_age_days = 28

[ecs]
enabled = false
ipv4_prefix_length = 24
ipv6_prefix_length = 56

[update]
keys = {}

[xfr]
enabled = false
allowed_subnets = []
notify_slaves = []

[acl]
allow_query = ['any']
allow_recursion = ['trusted-lan']
allow_transfer = ['none']

[acl.lists]
trusted-lan = ['127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16']

[views]
default = 'public'

[[views.entries]]
name = 'internal'
match_clients = ['trusted-lan']

[[views.entries]]
name = 'public'
match_clients = ['any']

[tls]
cert_file = ''
key_file = ''

[listeners]
dot = ':853'
doh = ':443'

[api]
listen = '127.0.0.1:8080'
auth_token = 'dev-token-change-me'
tls_cert = ''
tls_key = ''
`

// bootstrapDirectories are created on every startup when missing.
var bootstrapDirectories = []string{
	"./data",
	"./data/certs",
	"./zones",
	"./blocklists",
}

// Bootstrap ensures runtime directories exist and writes the embedded default
// configuration template when the target config file is missing.
func Bootstrap(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config path must not be empty")
	}

	for _, dir := range bootstrapDirectories {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", dir, err)
		}
	}

	if _, err := os.Stat(configPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat config %q: %w", configPath, err)
	}

	return writeDefaultConfig(configPath)
}

func writeDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, []byte(defaultConfigTemplate), 0o644); err != nil {
		return fmt.Errorf("write default config %q: %w", path, err)
	}

	return nil
}
