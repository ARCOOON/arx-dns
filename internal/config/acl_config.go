package config

import (
	"fmt"
	"strings"

	"github.com/ARCOOON/arx-dns/internal/acl"
)

// ACLConfig holds BIND9-style named ACL lists and global/zone policies.
type ACLConfig struct {
	Lists          map[string][]string      `toml:"lists" json:"lists"`
	AllowQuery     []string                 `toml:"allow_query" json:"allow_query"`
	AllowRecursion []string                 `toml:"allow_recursion" json:"allow_recursion"`
	AllowTransfer  []string                 `toml:"allow_transfer" json:"allow_transfer"`
	Zones          map[string]ZoneACLConfig `toml:"zones" json:"zones"`
}

// ZoneACLConfig overrides ACL directives for one authoritative zone apex.
type ZoneACLConfig struct {
	AllowQuery     []string `toml:"allow_query" json:"allow_query"`
	AllowRecursion []string `toml:"allow_recursion" json:"allow_recursion"`
	AllowTransfer  []string `toml:"allow_transfer" json:"allow_transfer"`
}

// ViewsConfig controls BIND-style view selection by client source.
type ViewsConfig struct {
	Default string      `toml:"default" json:"default"`
	Entries []ViewEntry `toml:"entries" json:"entries"`
}

// ViewEntry maps matching clients to a zone view name (public or internal).
type ViewEntry struct {
	Name         string   `toml:"name" json:"name"`
	MatchClients []string `toml:"match_clients" json:"match_clients"`
	UseECS       bool     `toml:"use_ecs" json:"use_ecs"`
}

// BuildPolicyEngine constructs the runtime ACL engine from configuration.
// Unset global directives inherit legacy recursive.trusted_subnets and xfr.allowed_subnets.
func (c Config) BuildPolicyEngine() (*acl.Engine, error) {
	named, err := acl.BuildNamedLists(c.ACL.Lists)
	if err != nil {
		return nil, err
	}

	global, err := c.buildGlobalPolicy(named)
	if err != nil {
		return nil, err
	}

	zones, err := c.buildZonePolicies(named)
	if err != nil {
		return nil, err
	}

	views, defaultView, err := c.buildViewRules(named)
	if err != nil {
		return nil, err
	}

	legacyRecursion, err := acl.ParseMatchList(c.Recursive.TrustedSubnets)
	if err != nil {
		return nil, fmt.Errorf("recursive.trusted_subnets: %w", err)
	}

	return acl.NewEngine(named, global, zones, views, defaultView, legacyRecursion), nil
}

func (c Config) buildGlobalPolicy(named map[string]*acl.MatchList) (acl.PolicySet, error) {
	var out acl.PolicySet
	var err error

	queryElems := c.ACL.AllowQuery
	if len(queryElems) == 0 {
		queryElems = []string{acl.KeywordAny}
	}
	out.AllowQuery, err = acl.ParseMatchList(queryElems)
	if err != nil {
		return out, fmt.Errorf("acl.allow_query: %w", err)
	}

	if len(c.ACL.AllowRecursion) > 0 {
		out.AllowRecursion, err = acl.ParseMatchList(c.ACL.AllowRecursion)
		if err != nil {
			return out, fmt.Errorf("acl.allow_recursion: %w", err)
		}
	}

	if len(c.ACL.AllowTransfer) > 0 {
		out.AllowTransfer, err = acl.ParseMatchList(c.ACL.AllowTransfer)
		if err != nil {
			return out, fmt.Errorf("acl.allow_transfer: %w", err)
		}
	} else if c.XFR.Enabled && len(c.XFR.AllowedSubnets) > 0 {
		out.AllowTransfer, err = acl.ParseMatchList(c.XFR.AllowedSubnets)
		if err != nil {
			return out, fmt.Errorf("xfr.allowed_subnets: %w", err)
		}
	} else {
		out.AllowTransfer, err = acl.ParseMatchList([]string{acl.KeywordNone})
		if err != nil {
			return out, fmt.Errorf("acl.allow_transfer default: %w", err)
		}
	}

	if err := acl.ValidateNamedReferences(out.AllowQuery, named); err != nil {
		return out, fmt.Errorf("acl.allow_query: %w", err)
	}
	if err := acl.ValidateNamedReferences(out.AllowRecursion, named); err != nil {
		return out, fmt.Errorf("acl.allow_recursion: %w", err)
	}
	if err := acl.ValidateNamedReferences(out.AllowTransfer, named); err != nil {
		return out, fmt.Errorf("acl.allow_transfer: %w", err)
	}

	return out, nil
}

func (c Config) buildZonePolicies(named map[string]*acl.MatchList) (map[string]acl.PolicySet, error) {
	out := make(map[string]acl.PolicySet, len(c.ACL.Zones))
	for apex, zoneCfg := range c.ACL.Zones {
		apex = normalizeACLZoneName(apex)
		if apex == "." {
			continue
		}
		var policy acl.PolicySet
		var err error

		if len(zoneCfg.AllowQuery) > 0 {
			policy.AllowQuery, err = acl.ParseMatchList(zoneCfg.AllowQuery)
			if err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_query: %w", apex, err)
			}
			if err := acl.ValidateNamedReferences(policy.AllowQuery, named); err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_query: %w", apex, err)
			}
		}
		if len(zoneCfg.AllowRecursion) > 0 {
			policy.AllowRecursion, err = acl.ParseMatchList(zoneCfg.AllowRecursion)
			if err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_recursion: %w", apex, err)
			}
			if err := acl.ValidateNamedReferences(policy.AllowRecursion, named); err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_recursion: %w", apex, err)
			}
		}
		if len(zoneCfg.AllowTransfer) > 0 {
			policy.AllowTransfer, err = acl.ParseMatchList(zoneCfg.AllowTransfer)
			if err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_transfer: %w", apex, err)
			}
			if err := acl.ValidateNamedReferences(policy.AllowTransfer, named); err != nil {
				return nil, fmt.Errorf("acl.zones[%q].allow_transfer: %w", apex, err)
			}
		}
		out[apex] = policy
	}
	return out, nil
}

func (c Config) buildViewRules(named map[string]*acl.MatchList) ([]acl.ViewRule, acl.ZoneView, error) {
	defaultView := acl.ViewPublic
	if raw := strings.TrimSpace(c.Views.Default); raw != "" {
		view, err := parseACLZoneView(raw)
		if err != nil {
			return nil, "", fmt.Errorf("views.default: %w", err)
		}
		defaultView = view
	}

	if len(c.Views.Entries) == 0 {
		return nil, defaultView, nil
	}

	rules := make([]acl.ViewRule, 0, len(c.Views.Entries))
	for i, entry := range c.Views.Entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			return nil, "", fmt.Errorf("views.entries[%d].name must not be empty", i)
		}
		if _, err := parseACLZoneView(name); err != nil {
			return nil, "", fmt.Errorf("views.entries[%d].name: %w", i, err)
		}
		if len(entry.MatchClients) == 0 {
			return nil, "", fmt.Errorf("views.entries[%d].match_clients must not be empty", i)
		}
		match, err := acl.ParseMatchList(entry.MatchClients)
		if err != nil {
			return nil, "", fmt.Errorf("views.entries[%d].match_clients: %w", i, err)
		}
		if err := acl.ValidateNamedReferences(match, named); err != nil {
			return nil, "", fmt.Errorf("views.entries[%d].match_clients: %w", i, err)
		}
		rules = append(rules, acl.ViewRule{
			Name:         name,
			MatchClients: match,
			UseECS:       entry.UseECS,
		})
	}
	return rules, defaultView, nil
}

func (c Config) validateACL() error {
	_, err := c.BuildPolicyEngine()
	return err
}

func normalizeACLZoneName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "." {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func parseACLZoneView(raw string) (acl.ZoneView, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(acl.ViewPublic):
		return acl.ViewPublic, nil
	case string(acl.ViewInternal):
		return acl.ViewInternal, nil
	default:
		return "", fmt.Errorf("invalid view %q: must be public or internal", raw)
	}
}
