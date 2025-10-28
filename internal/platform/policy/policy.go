package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/topdown"
)

// Config defines policy compilation inputs.
type Config struct {
	Query           string
	Modules         map[string]string
	Data            map[string]any
	EvalTimeout     time.Duration
	CacheTTL        time.Duration
	MaxCacheEntries int
	Tracer          topdown.Tracer
	EnableMetrics   bool
}

// Decision captures the outcome from policy evaluation.
type Decision struct {
	Allow       bool
	Obligations []string
	Metadata    map[string]any
	RawResult   any
}

// Engine encapsulates compiled rego query with caching.
type Engine struct {
	query         rego.PreparedEvalQuery
	timeout       time.Duration
	cache         *decisionCache
	enableMetrics bool
	evalOpts      []rego.EvalOption
}

// New constructs policy engine.
func New(ctx context.Context, cfg Config) (*Engine, error) {
	if cfg.Query == "" {
		return nil, errors.New("policy: query cannot be empty")
	}

	opts := []func(*rego.Rego){
		rego.Query(cfg.Query),
	}
	for path, module := range cfg.Modules {
		opts = append(opts, rego.Module(path, module))
	}
	var evalOpts []rego.EvalOption
	if cfg.Tracer != nil {
		evalOpts = append(evalOpts, rego.EvalTracer(cfg.Tracer))
	}
	if cfg.Data != nil {
		opts = append(opts, rego.Store(inmem.NewFromObject(cfg.Data)))
	}

	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compile: %w", err)
	}

	cache := newDecisionCache(cfg.MaxCacheEntries, cfg.CacheTTL)
	timeout := cfg.EvalTimeout
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}

	return &Engine{
		query:         prepared,
		timeout:       timeout,
		cache:         cache,
		enableMetrics: cfg.EnableMetrics,
		evalOpts:      evalOpts,
	}, nil
}

// Evaluate runs prepared policy against provided input.
func (e *Engine) Evaluate(ctx context.Context, input any) (Decision, error) {
	var zero Decision
	if e == nil {
		return zero, errors.New("policy: engine is nil")
	}

	cacheKey, err := fingerprintInput(input)
	if err != nil {
		return zero, err
	}
	if decision, ok := e.cache.Get(cacheKey); ok {
		return decision, nil
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	evalOptions := append([]rego.EvalOption{rego.EvalInput(input)}, e.evalOpts...)
	rs, err := e.query.Eval(ctx, evalOptions...)
	if err != nil {
		return zero, fmt.Errorf("policy: eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return zero, errors.New("policy: empty result set")
	}

	decision, err := normalizeResult(rs[0].Expressions[0].Value)
	if err != nil {
		return zero, err
	}

	e.cache.Set(cacheKey, decision)
	return decision, nil
}

func normalizeResult(val any) (Decision, error) {
	switch v := val.(type) {
	case bool:
		return Decision{Allow: v, RawResult: v}, nil
	case map[string]any:
		decision := Decision{
			Allow:     true,
			RawResult: v,
			Metadata:  map[string]any{},
		}
		if allow, ok := v["allow"].(bool); ok {
			decision.Allow = allow
		}
		if obligations, ok := v["obligations"].([]any); ok {
			for _, o := range obligations {
				if str, ok := o.(string); ok {
					decision.Obligations = append(decision.Obligations, str)
				}
			}
		}
		if metadata, ok := v["metadata"].(map[string]any); ok {
			decision.Metadata = metadata
		}
		return decision, nil
	default:
		return Decision{}, fmt.Errorf("policy: unsupported result type %T", v)
	}
}

// decisionCache provides bounded ttl cache.
type decisionCache struct {
	entries map[string]cacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

type cacheEntry struct {
	value     Decision
	expiresAt time.Time
}

func newDecisionCache(max int, ttl time.Duration) *decisionCache {
	if max <= 0 {
		max = 512
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &decisionCache{
		entries: make(map[string]cacheEntry, max),
		maxSize: max,
		ttl:     ttl,
	}
}

func (c *decisionCache) Get(key string) (Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return Decision{}, false
	}
	return entry.value, true
}

func (c *decisionCache) Set(key string, decision Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[key] = cacheEntry{
		value:     decision,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *decisionCache) evict() {
	var oldestKey string
	var oldest time.Time
	for k, v := range c.entries {
		if oldestKey == "" || v.expiresAt.Before(oldest) {
			oldestKey = k
			oldest = v.expiresAt
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func fingerprintInput(input any) (string, error) {
	bytes, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("policy: input marshal: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}
