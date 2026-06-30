package runtime

import (
	"fmt"
	"log/slog"

	"github.com/ARCOOON/arx-dns/internal/acl"
	"github.com/ARCOOON/arx-dns/internal/config"
	"github.com/ARCOOON/arx-dns/internal/dnsproc"
	"github.com/ARCOOON/arx-dns/internal/dnssec"
	"github.com/ARCOOON/arx-dns/internal/firewall"
	"github.com/ARCOOON/arx-dns/internal/logger"
	"github.com/ARCOOON/arx-dns/internal/network"
	"github.com/ARCOOON/arx-dns/internal/storage"
	"github.com/ARCOOON/arx-dns/internal/telemetry"
)

// Applier applies non-critical configuration changes at runtime without restarting listeners.
type Applier struct {
	Processor    *dnsproc.Processor
	Forwarder    *dnsproc.Forwarder
	RateLimit    *network.RateLimiter
	TrustedACL   *network.ACL
	XFRACL       *network.ACL
	PolicyEngine *acl.Engine
	Firewall     *firewall.Engine
	Store        *storage.Memory
	Telemetry    *telemetry.DB
	Logger       *slog.Logger
}

// Apply updates hot-reloadable services from cfg.
func (a *Applier) Apply(cfg config.Config) error {
	if a == nil {
		return nil
	}

	logCfg := logger.Config{
		Level: cfg.Server.LogLevel,
		Rotation: logger.RotationConfig{
			FilePath:   cfg.Logging.FilePath,
			MaxSizeMB:  cfg.Logging.MaxSizeMB,
			MaxBackups: cfg.Logging.MaxBackups,
			MaxAgeDays: cfg.Logging.MaxAgeDays,
		},
	}
	if a.Telemetry != nil {
		if err := logger.UpdateConfig(a.Telemetry.Main(), logCfg); err != nil {
			return fmt.Errorf("apply logging config: %w", err)
		}
	} else if err := logger.SetLevel(cfg.Server.LogLevel); err != nil {
		return fmt.Errorf("apply log level: %w", err)
	}

	if a.RateLimit != nil {
		a.RateLimit.Reconfigure(cfg.RateLimit)
	}

	trustedACL, err := network.ACLFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("parse trusted subnets: %w", err)
	}
	a.TrustedACL = trustedACL

	xfrACL, err := network.ACLFromXFRConfig(cfg)
	if err != nil {
		return fmt.Errorf("parse xfr subnets: %w", err)
	}
	a.XFRACL = xfrACL

	policyEngine, err := cfg.BuildPolicyEngine()
	if err != nil {
		return fmt.Errorf("parse acl/views: %w", err)
	}
	a.PolicyEngine = policyEngine

	if a.Processor != nil {
		a.Processor.ApplyRuntimeConfig(cfg, trustedACL, xfrACL, policyEngine)
	}

	if err := dnssec.ApplyCustomAnchors(cfg.Security.NormalizedRootAnchors()); err != nil {
		return fmt.Errorf("apply root anchors: %w", err)
	}

	if cfg.ResolverMode() == "forward" && a.Forwarder != nil {
		if err := a.Forwarder.SetUpstreams(cfg.Recursive.Upstreams); err != nil {
			return fmt.Errorf("apply upstreams: %w", err)
		}
		a.Forwarder.SetDNSSECValidation(cfg.Security.DNSSECValidation)
		a.Forwarder.SetECS(cfg.ECS.Enabled, uint8(cfg.ECS.IPv4PrefixLength), uint8(cfg.ECS.IPv6PrefixLength))
	}
	if cfg.ResolverMode() == "iterative" && a.Processor != nil && a.Processor.IterativeResolver() != nil {
		a.Processor.IterativeResolver().SetDNSSECValidation(cfg.Security.DNSSECValidation)
	}

	if a.Firewall != nil && a.Telemetry != nil {
		fwAction, err := firewall.ParseBlockAction(cfg.Firewall.BlockAction)
		if err != nil {
			return fmt.Errorf("parse firewall block action: %w", err)
		}
		a.Firewall.SetAction(fwAction)
		firewall.Load(cfg.Firewall, a.Telemetry.Main(), a.Firewall, a.Logger)
	}

	if a.Store != nil {
		storage.LoadZones(cfg.Zones, a.Store, a.Logger)
	}

	return nil
}
