package rotation

import (
	"sync"
	"time"
)

// Config defines rekey thresholds.
type Config struct {
	Interval   time.Duration
	MaxPackets uint64
	Skew       time.Duration
}

// Manager tracks packet counts and elapsed time to signal rotation events.
type Manager struct {
	mu      sync.Mutex
	cfg     Config
	start   time.Time
	packets uint64
	epoch   uint64
}

// New creates a rotation manager starting at the provided time and epoch.
func New(cfg Config, start time.Time, epoch uint64) *Manager {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Minute
	}
	if cfg.Skew <= 0 {
		cfg.Skew = 5 * time.Second
	}
	return &Manager{
		cfg:   cfg,
		start: start,
		epoch: epoch,
	}
}

// Record increments packet counts and returns whether rotation should occur.
func (m *Manager) Record(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets++
	return m.shouldRotateLocked(now)
}

// ShouldRotate checks thresholds without mutating state.
func (m *Manager) ShouldRotate(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shouldRotateLocked(now)
}

// NextEpoch returns the current epoch identifier.
func (m *Manager) NextEpoch() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epoch
}

// Reset resets counters and advances epoch.
func (m *Manager) Reset(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.start = now
	m.packets = 0
	m.epoch++
}

func (m *Manager) shouldRotateLocked(now time.Time) bool {
	if m.cfg.MaxPackets > 0 && m.packets >= m.cfg.MaxPackets {
		return true
	}
	skew := m.cfg.Skew
	if skew >= m.cfg.Interval {
		skew = 0
	}
	deadline := m.start.Add(m.cfg.Interval - skew)
	return !now.Before(deadline)
}
