package config

import (
	"fmt"
	"strconv"
	"strings"
)

type summarySection struct {
	tag    string
	fields string
}

// FormatStartupSummary returns a human-readable, block-aligned configuration
// summary grouped by TOML section for cohesive multiline startup logging.
func (c Config) FormatStartupSummary(configPath string) string {
	sections := c.startupSummarySections(configPath)

	maxTag := 0
	for _, s := range sections {
		if len(s.tag) > maxTag {
			maxTag = len(s.tag)
		}
	}

	var b strings.Builder
	b.WriteString("configuration loaded successfully:\n")
	for _, s := range sections {
		pad := strings.Repeat(" ", maxTag-len(s.tag))
		fmt.Fprintf(&b, "  %s%s %s\n", s.tag, pad, s.fields)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (c Config) startupSummarySections(configPath string) []summarySection {
	return []summarySection{
		{
			tag: "[server]",
			fields: joinSummaryFields(
				summaryStr("config", configPath),
				summaryStr("listen", c.ListenAddress()),
				summaryInt("event_loops", c.Server.EventLoops),
				summaryStr("log_level", c.Server.LogLevel),
			),
		},
		{
			tag: "[tls]",
			fields: joinSummaryFields(
				summaryStr("cert_file", c.TLS.CertFile),
				summaryStr("key_file", c.TLS.KeyFile),
			),
		},
		{
			tag: "[listeners]",
			fields: joinSummaryFields(
				summaryStr("dot", c.Listeners.DoT),
				summaryStr("doh", c.Listeners.DoH),
				summaryBool("encrypted_dns", c.EncryptedDNSEnabled()),
			),
		},
		{
			tag: "[api]",
			fields: joinSummaryFields(
				summaryStr("listen", c.API.Listen),
				summaryBool("tls", strings.TrimSpace(c.API.TLSCert) != "" && strings.TrimSpace(c.API.TLSKey) != ""),
			),
		},
		{
			tag: "[zones]",
			fields: joinSummaryFields(
				summaryStr("directory", c.Zones.Directory),
			),
		},
		{
			tag: "[recursive]",
			fields: joinSummaryFields(
				summaryInt("upstreams", len(c.Recursive.Upstreams)),
				summaryInt("trusted_subnets", len(c.Recursive.TrustedSubnets)),
			),
		},
		{
			tag: "[resolver]",
			fields: joinSummaryFields(
				summaryStr("mode", c.ResolverMode()),
				summaryBool("qname_minimization", c.Resolver.QNameMinimization),
				summaryStr("root_hints_file", c.Resolver.RootHintsFile),
				summaryBool("auto_update_root_hints", c.Resolver.AutoUpdateRootHints),
			),
		},
		{
			tag: "[firewall]",
			fields: joinSummaryFields(
				summaryStr("blocklists", c.Firewall.BlocklistsDirectory),
				summaryStr("block_action", c.Firewall.BlockAction),
			),
		},
		{
			tag: "[rpz]",
			fields: joinSummaryFields(
				summaryBool("enabled", c.RPZ.Enabled),
				summaryInt("policies", len(c.RPZ.Policies)),
			),
		},
		{
			tag: "[security]",
			fields: joinSummaryFields(
				summaryBool("dnssec_validation", c.Security.DNSSECValidation),
				summaryBool("dns_cookies_enabled", c.Security.DNSCookiesEnabled),
				summaryBool("dns_cookie_secret", strings.TrimSpace(c.Security.DNSCookieSecret) != ""),
			),
		},
		{
			tag: "[rate_limit]",
			fields: joinSummaryFields(
				summaryBool("enabled", c.RateLimit.Enabled),
				summaryInt("requests_per_second", c.RateLimit.RequestsPerSecond),
				summaryInt("burst", c.RateLimit.Burst),
			),
		},
		{
			tag: "[ecs]",
			fields: joinSummaryFields(
				summaryBool("enabled", c.ECS.Enabled),
				summaryInt("ipv4_prefix_length", c.ECS.IPv4PrefixLength),
				summaryInt("ipv6_prefix_length", c.ECS.IPv6PrefixLength),
			),
		},
		{
			tag: "[logging]",
			fields: joinSummaryFields(
				summaryStr("file_path", c.Logging.FilePath),
				summaryInt("max_size_mb", c.Logging.MaxSizeMB),
				summaryInt("max_backups", c.Logging.MaxBackups),
				summaryInt("max_age_days", c.Logging.MaxAgeDays),
			),
		},
		{
			tag: "[update]",
			fields: joinSummaryFields(
				summaryInt("keys", len(c.Update.Keys)),
			),
		},
		{
			tag: "[xfr]",
			fields: joinSummaryFields(
				summaryBool("enabled", c.XFR.Enabled),
				summaryInt("allowed_subnets", len(c.XFR.AllowedSubnets)),
				summaryInt("notify_slaves", len(c.XFR.NotifySlaves)),
			),
		},
		{
			tag: "[acl]",
			fields: joinSummaryFields(
				summaryInt("match_lists", len(c.ACL.Lists)),
				summaryStr("queries", formatMatchListSummary(c.ACL.AllowQuery)),
				summaryStr("recursion", formatMatchListSummary(c.ACL.AllowRecursion)),
				summaryStr("transfer", formatMatchListSummary(c.ACL.AllowTransfer)),
				summaryInt("zone_overrides", len(c.ACL.Zones)),
			),
		},
		{
			tag: "[views]",
			fields: joinSummaryFields(
				summaryStr("default", c.Views.Default),
				summaryInt("entries", len(c.Views.Entries)),
			),
		},
	}
}

func joinSummaryFields(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	return strings.Join(nonEmpty, " ")
}

func summaryStr(key, value string) string {
	return key + "=" + strconv.Quote(value)
}

func summaryInt(key string, value int) string {
	return key + "=" + strconv.Itoa(value)
}

func summaryBool(key string, value bool) string {
	return key + "=" + strconv.FormatBool(value)
}

func formatMatchListSummary(elems []string) string {
	if len(elems) == 0 {
		return "default"
	}
	parts := make([]string, 0, len(elems))
	for _, elem := range elems {
		elem = strings.TrimSpace(elem)
		if elem != "" {
			parts = append(parts, elem)
		}
	}
	if len(parts) == 0 {
		return "default"
	}
	return strings.Join(parts, ",")
}
