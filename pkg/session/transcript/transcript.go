package transcript

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/zeebo/blake3"
)

// Accumulator incrementally records handshake artefacts into a domain-separated hash.
type Accumulator struct {
	mu     sync.Mutex
	hasher *blake3.Hasher
	logs   []entry
}

type entry struct {
	Label string
	Data  json.RawMessage
}

// New constructs a fresh transcript accumulator.
func New(domain string) *Accumulator {
	h := blake3.New()
	_, _ = h.Write([]byte("domain:"))
	_, _ = h.Write([]byte(domain))
	return &Accumulator{
		hasher: h,
		logs:   make([]entry, 0, 8),
	}
}

// Append serialises the provided value and folds it into the transcript hash.
func (a *Accumulator) Append(label string, v any) error {
	if label == "" {
		return fmt.Errorf("transcript: label required")
	}

	serialized, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("transcript: marshal %s: %w", label, err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.hasher.Write([]byte(label)); err != nil {
		return fmt.Errorf("transcript: write label: %w", err)
	}
	length := uint64(len(serialized))
	lenBuf := make([]byte, 8)
	for i := uint(0); i < 8; i++ {
		lenBuf[i] = byte(length >> (56 - 8*i))
	}
	if _, err := a.hasher.Write(lenBuf); err != nil {
		return fmt.Errorf("transcript: write length: %w", err)
	}
	if _, err := a.hasher.Write(serialized); err != nil {
		return fmt.Errorf("transcript: write body: %w", err)
	}

	a.logs = append(a.logs, entry{Label: label, Data: serialized})
	return nil
}

// Snapshot returns the current transcript commitment.
func (a *Accumulator) Snapshot() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot := a.hasher.Clone().Sum(nil)
	return append([]byte(nil), snapshot...)
}

// Entries exposes the recorded sequence for auditing.
func (a *Accumulator) Entries() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.logs))
	for i, e := range a.logs {
		out[i] = fmt.Sprintf("%s:%s", e.Label, string(e.Data))
	}
	return out
}
