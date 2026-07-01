package config

import (
	"fmt"

	"github.com/ARCOOON/arx-dns/internal/rpz"
)

// RPZConfig controls the Response Policy Zone engine.
type RPZConfig struct {
	Enabled  bool              `toml:"enabled" json:"enabled"`
	Policies []RPZPolicyConfig `toml:"policies" json:"policies"`
}

// RPZPolicyConfig defines one RPZ trigger pattern and response action.
type RPZPolicyConfig struct {
	Pattern string `toml:"pattern" json:"pattern"`
	Action  string `toml:"action" json:"action"`
	Target  string `toml:"target" json:"target"`
}

// BuildRPZEngine constructs the runtime RPZ engine from configuration.
// When RPZ is disabled, nil is returned without error.
func (c Config) BuildRPZEngine() (*rpz.Engine, error) {
	if !c.RPZ.Enabled {
		return nil, nil
	}

	engine := rpz.New()
	policies := make([]rpz.Policy, 0, len(c.RPZ.Policies))
	for i, policy := range c.RPZ.Policies {
		action, err := rpz.ParseAction(policy.Action)
		if err != nil {
			return nil, fmt.Errorf("rpz.policies[%d].action: %w", i, err)
		}
		policies = append(policies, rpz.Policy{
			Pattern: policy.Pattern,
			Action:  action,
			Target:  policy.Target,
		})
	}
	if err := engine.ReplacePolicies(policies); err != nil {
		return nil, fmt.Errorf("rpz policies: %w", err)
	}
	return engine, nil
}

func (c Config) validateRPZ() error {
	if !c.RPZ.Enabled {
		return nil
	}
	for i, policy := range c.RPZ.Policies {
		if _, err := rpz.ParseAction(policy.Action); err != nil {
			return fmt.Errorf("rpz.policies[%d].action: %w", i, err)
		}
		action, _ := rpz.ParseAction(policy.Action)
		probe := rpz.New()
		if err := probe.AddPolicy(policy.Pattern, action, policy.Target); err != nil {
			return fmt.Errorf("rpz.policies[%d]: %w", i, err)
		}
	}
	return nil
}
