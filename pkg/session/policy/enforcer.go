package policy

import (
	"fmt"
	"time"
)

// Config enumerates allowed session characteristics.
type Config struct {
	AllowedModes []string
	AllowedAEAD  []string
	MinRotation  time.Duration
	MaxRotation  time.Duration
}

// Parameters describes a negotiated session.
type Parameters struct {
	Mode           string
	AEAD           string
	RotationWindow time.Duration
}

// Enforcer validates session parameters.
type Enforcer struct {
	modes map[string]struct{}
	aeads map[string]struct{}
	cfg   Config
}

// New builds an Enforcer from the given configuration.
func New(cfg Config) *Enforcer {
	modes := make(map[string]struct{}, len(cfg.AllowedModes))
	for _, m := range cfg.AllowedModes {
		modes[m] = struct{}{}
	}
	aeads := make(map[string]struct{}, len(cfg.AllowedAEAD))
	for _, a := range cfg.AllowedAEAD {
		aeads[a] = struct{}{}
	}
	if cfg.MinRotation <= 0 {
		cfg.MinRotation = 5 * time.Minute
	}
	if cfg.MaxRotation <= 0 {
		cfg.MaxRotation = 60 * time.Minute
	}
	return &Enforcer{modes: modes, aeads: aeads, cfg: cfg}
}

// Validate ensures the parameters respect configured policy.
func (e *Enforcer) Validate(params Parameters) error {
	if len(e.modes) > 0 {
		if _, ok := e.modes[params.Mode]; !ok {
			return fmt.Errorf("policy: mode %q not permitted", params.Mode)
		}
	}
	if len(e.aeads) > 0 {
		if _, ok := e.aeads[params.AEAD]; !ok {
			return fmt.Errorf("policy: AEAD %q not permitted", params.AEAD)
		}
	}
	if params.RotationWindow < e.cfg.MinRotation {
		return fmt.Errorf("policy: rotation interval %s below minimum %s", params.RotationWindow, e.cfg.MinRotation)
	}
	if params.RotationWindow > e.cfg.MaxRotation {
		return fmt.Errorf("policy: rotation interval %s exceeds maximum %s", params.RotationWindow, e.cfg.MaxRotation)
	}
	return nil
}
