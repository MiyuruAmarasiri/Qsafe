package compliance

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"time"
)

// Status enumerates compliance result states.
type Status string

const (
	StatusUnknown Status = "UNKNOWN"
	StatusPass    Status = "PASS"
	StatusWarn    Status = "WARN"
	StatusFail    Status = "FAIL"
)

// Evidence anchors structured data to decisions.
type Evidence struct {
	Key       string
	Value     string
	Critical  bool
	Timestamp time.Time
}

// Result captures a compliance check outcome.
type Result struct {
	Name      string
	Status    Status
	Details   string
	Evidence  []Evidence
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

// Check defines compliance validation contract.
type Check interface {
	Name() string
	Run(ctx context.Context) Result
}

// CheckFunc adapts functions to Check interface.
type CheckFunc func(ctx context.Context) Result

// Name returns synthetic name when not provided.
func (f CheckFunc) Name() string {
	return runtimeFunctionName(f)
}

// Run executes the function.
func (f CheckFunc) Run(ctx context.Context) Result {
	return f(ctx)
}

// Checker orchestrates check execution and aggregation.
type Checker struct {
	mu     sync.RWMutex
	checks []Check
}

// NewChecker builds aggregator from provided checks.
func NewChecker(checks ...Check) *Checker {
	return &Checker{checks: checks}
}

// Register appends additional checks at runtime.
func (c *Checker) Register(checks ...Check) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks = append(c.checks, checks...)
}

// Evaluate runs all registered checks and returns summary.
func (c *Checker) Evaluate(ctx context.Context) Summary {
	start := time.Now()
	checks := c.snapshot()
	results := make([]Result, len(checks))

	var wg sync.WaitGroup
	for idx, check := range checks {
		wg.Add(1)
		go func(i int, chk Check) {
			defer wg.Done()
			begin := time.Now()
			result := chk.Run(ctx)
			if result.Name == "" {
				result.Name = chk.Name()
			}
			result.Duration = time.Since(begin)
			if result.Status == "" {
				result.Status = StatusUnknown
			}
			if result.Timestamp.IsZero() {
				result.Timestamp = time.Now()
			}
			results[i] = result
		}(idx, check)
	}
	wg.Wait()

	summary := Summary{
		Results:     results,
		GeneratedAt: time.Now(),
		Elapsed:     time.Since(start),
	}
	for _, result := range results {
		switch result.Status {
		case StatusFail:
			summary.Failed = append(summary.Failed, result)
		case StatusWarn:
			summary.Warnings = append(summary.Warnings, result)
		}
		if result.Error != nil {
			summary.Errors = append(summary.Errors, fmt.Errorf("%s: %w", result.Name, result.Error))
		}
	}
	return summary
}

func (c *Checker) snapshot() []Check {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Check, len(c.checks))
	copy(out, c.checks)
	return out
}

// Summary aggregates compliance posture.
type Summary struct {
	Results     []Result
	Failed      []Result
	Warnings    []Result
	Errors      []error
	GeneratedAt time.Time
	Elapsed     time.Duration
}

// Healthy returns true when no failures or warnings present.
func (s Summary) Healthy() bool {
	return len(s.Failed) == 0 && len(s.Warnings) == 0
}

// Error aggregates errors for easy reporting.
func (s Summary) Error() error {
	if len(s.Errors) == 0 {
		return nil
	}
	return errors.Join(s.Errors...)
}

func runtimeFunctionName(i any) string {
	if i == nil {
		return "anonymous"
	}
	val := reflect.ValueOf(i)
	if val.Kind() != reflect.Func {
		return fmt.Sprintf("%T", i)
	}
	if fn := runtime.FuncForPC(val.Pointer()); fn != nil {
		return fn.Name()
	}
	return fmt.Sprintf("%T", i)
}
