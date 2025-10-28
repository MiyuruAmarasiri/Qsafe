package logging

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type contextKey struct{}

// Config captures logger bootstrap options.
type Config struct {
	ServiceName        string
	Environment        string
	Level              string
	OutputPaths        []string
	ErrorOutput        []string
	SamplingInitial    int
	SamplingThereafter int
	RedactionRules     []RedactionRule
	CorrelateWithID    bool
}

// RedactionRule masks field values before emission.
type RedactionRule struct {
	Key         string
	Pattern     string
	Replacement string
	compiled    *regexp.Regexp
}

// Global returns a process-wide logger configured with zap.Logger.
// The returned cleanup function must be invoked on shutdown to flush buffers.
func Global(cfg Config) (*zap.Logger, func(context.Context) error, error) {
	if cfg.ServiceName == "" {
		return nil, nil, errors.New("logging: service name must be provided")
	}

	level := zap.InfoLevel
	if cfg.Level != "" {
		if err := level.UnmarshalText([]byte(strings.ToLower(cfg.Level))); err != nil {
			return nil, nil, fmt.Errorf("logging: invalid level %q: %w", cfg.Level, err)
		}
	}

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeDuration: zapcore.MillisDurationEncoder,
	}

	outputs := cfg.OutputPaths
	if len(outputs) == 0 {
		outputs = []string{"stdout"}
	}
	errOutputs := cfg.ErrorOutput
	if len(errOutputs) == 0 {
		errOutputs = []string{"stderr"}
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.NewMultiWriteSyncer(toWriters(outputs)...),
		level,
	)

	if cfg.SamplingInitial > 0 && cfg.SamplingThereafter > 0 {
		core = zapcore.NewSamplerWithOptions(
			core,
			time.Second,
			cfg.SamplingInitial,
			cfg.SamplingThereafter,
		)
	}

	compiled, err := compileRules(cfg.RedactionRules)
	if err != nil {
		return nil, nil, fmt.Errorf("logging: %w", err)
	}
	if len(compiled) > 0 {
		core = &redactingCore{Core: core, rules: compiled}
	}

	opts := []zap.Option{
		zap.AddCaller(),
		zap.Fields(
			zap.String("svc", cfg.ServiceName),
			zap.String("env", cfg.Environment),
		),
	}
	if len(errOutputs) > 0 {
		opts = append(opts, zap.ErrorOutput(
			zapcore.NewMultiWriteSyncer(toWriters(errOutputs)...),
		))
	}

	logger := zap.New(core, opts...)

	cleanup := func(ctx context.Context) error {
		done := make(chan struct{})
		var flushErr error
		go func() {
			defer close(done)
			flushErr = logger.Sync()
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return flushErr
		}
	}

	if cfg.CorrelateWithID {
		logger = logger.WithOptions(zap.AddCallerSkip(1))
	}

	return logger, cleanup, nil
}

func toWriters(paths []string) []zapcore.WriteSyncer {
	writers := make([]zapcore.WriteSyncer, 0, len(paths))
	for _, p := range paths {
		switch p {
		case "stdout":
			writers = append(writers, zapcore.Lock(zapcore.AddSync(os.Stdout)))
		case "stderr":
			writers = append(writers, zapcore.Lock(zapcore.AddSync(os.Stderr)))
		default:
			file, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
			if err != nil {
				continue
			}
			writers = append(writers, zapcore.Lock(zapcore.AddSync(file)))
		}
	}
	return writers
}

type redactingCore struct {
	zapcore.Core
	rules []compiledRule
}

type compiledRule struct {
	key         string
	replacement string
	pattern     *regexp.Regexp
}

func compileRules(rules []RedactionRule) ([]compiledRule, error) {
	var compiled []compiledRule
	for _, r := range rules {
		if r.Key == "" && r.Pattern == "" {
			continue
		}
		repl := r.Replacement
		if repl == "" {
			repl = "[REDACTED]"
		}
		if r.Pattern != "" {
			regex, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid redaction pattern %q: %w", r.Pattern, err)
			}
			compiled = append(compiled, compiledRule{
				key:         r.Key,
				replacement: repl,
				pattern:     regex,
			})
			continue
		}
		compiled = append(compiled, compiledRule{
			key:         r.Key,
			replacement: repl,
		})
	}
	return compiled, nil
}

func (c *redactingCore) With(fields []zapcore.Field) zapcore.Core {
	return &redactingCore{
		Core:  c.Core.With(fields),
		rules: c.rules,
	}
}

func (c *redactingCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *redactingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	for i := range fields {
		fields[i] = c.redactField(fields[i])
	}
	return c.Core.Write(entry, fields)
}

func (c *redactingCore) redactField(field zapcore.Field) zapcore.Field {
	if len(c.rules) == 0 {
		return field
	}
	for _, rule := range c.rules {
		if rule.key != "" && field.Key != rule.key {
			continue
		}
		switch field.Type {
		case zapcore.StringType:
			field.String = rule.apply(field.String)
		case zapcore.StringerType:
			if stringer, ok := field.Interface.(fmt.Stringer); ok {
				field.Interface = nil
				field.Type = zapcore.StringType
				field.String = rule.apply(stringer.String())
			}
		case zapcore.ErrorType:
			if errVal, ok := field.Interface.(error); ok {
				field.Interface = nil
				field.Type = zapcore.StringType
				field.String = rule.apply(errVal.Error())
			}
		}
	}
	return field
}

func (r compiledRule) apply(value string) string {
	if r.pattern == nil {
		return r.replacement
	}
	return r.pattern.ReplaceAllString(value, r.replacement)
}

// Inject attaches logger to context.
func Inject(ctx context.Context, logger *zap.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

// From extracts logger from context or returns the provided fallback.
func From(ctx context.Context, fallback *zap.Logger) *zap.Logger {
	if ctx == nil {
		return fallback
	}
	if logger, ok := ctx.Value(contextKey{}).(*zap.Logger); ok {
		return logger
	}
	return fallback
}

// Correlator creates per-request loggers with correlation identifier.
type Correlator struct {
	key      string
	generate func() string
	seen     sync.Map
}

// NewCorrelator instantiates correlation helper.
func NewCorrelator(key string, generator func() string) *Correlator {
	if key == "" {
		key = "correlation_id"
	}
	if generator == nil {
		generator = defaultID
	}
	return &Correlator{
		key:      key,
		generate: generator,
	}
}

// Decorate attaches correlation id to logger and context.
func (c *Correlator) Decorate(ctx context.Context, logger *zap.Logger) (context.Context, *zap.Logger, string) {
	if c == nil {
		return ctx, logger, ""
	}
	id := c.generate()
	if _, loaded := c.seen.LoadOrStore(id, struct{}{}); loaded {
		id = c.generate()
	}
	child := logger.With(zap.String(c.key, id))
	return Inject(ctx, child), child, id
}

func defaultID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
