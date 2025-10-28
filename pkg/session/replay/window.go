package replay

import (
	"errors"
	"sync"
)

// Window provides monotonic sequence enforcement with bounded memory.
type Window struct {
	mu      sync.Mutex
	depth   uint64
	highest uint64
	seen    map[uint64]struct{}
}

// Config controls the replay protection behaviour.
type Config struct {
	Depth uint64
}

// ErrDuplicate indicates the sequence was already accepted.
var ErrDuplicate = errors.New("replay: duplicate sequence")

// ErrStale indicates the sequence is older than the acceptable window.
var ErrStale = errors.New("replay: stale sequence")

// New creates a replay window with the provided depth.
func New(cfg Config) *Window {
	depth := cfg.Depth
	if depth == 0 {
		depth = 2048
	}
	return &Window{
		depth: depth,
		seen:  make(map[uint64]struct{}, int(depth)),
	}
}

// Accept validates and records the provided sequence number.
func (w *Window) Accept(seq uint64) error {
	if seq == 0 {
		return errors.New("replay: sequence must start at 1")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.highest == 0 {
		w.highest = seq
		w.seen[seq] = struct{}{}
		return nil
	}

	if seq > w.highest {
		w.highest = seq
		w.seen[seq] = struct{}{}
		w.prune()
		return nil
	}

	if w.highest-seq >= w.depth {
		return ErrStale
	}
	if _, exists := w.seen[seq]; exists {
		return ErrDuplicate
	}

	w.seen[seq] = struct{}{}
	return nil
}

// Highest returns the highest sequence observed so far.
func (w *Window) Highest() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highest
}

func (w *Window) prune() {
	if w.depth == 0 {
		return
	}
	var threshold uint64
	if w.highest > w.depth {
		threshold = w.highest - w.depth
	}
	for seq := range w.seen {
		if seq <= threshold {
			delete(w.seen, seq)
		}
	}
}
