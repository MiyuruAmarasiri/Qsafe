package tracing

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config defines exporter and sampling configuration.
type Config struct {
	Endpoint          string
	Insecure          bool
	ServiceName       string
	Environment       string
	Attributes        map[string]string
	SampleRatio       float64
	Timeout           time.Duration
	ResourceDetectors []resource.Detector
	TLSConfig         *tls.Config
	Headers           map[string]string
}

// Provider wraps the tracer provider and shutdown hook.
type Provider struct {
	TracerProvider *sdktrace.TracerProvider
	shutdown       func(context.Context) error
}

// New configures OTLP trace pipeline and registers global provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ServiceName == "" {
		return nil, errors.New("tracing: service name is required")
	}

	resAttrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(cfg.ServiceName),
		semconv.ServiceVersionKey.String(buildVersion()),
		semconv.DeploymentEnvironmentKey.String(cfg.Environment),
	}
	for k, v := range cfg.Attributes {
		resAttrs = append(resAttrs, attribute.String(k, v))
	}

	opts := []resource.Option{resource.WithAttributes(resAttrs...)}
	if len(cfg.ResourceDetectors) > 0 {
		opts = append(opts, resource.WithDetectors(cfg.ResourceDetectors...))
	}

	res, err := resource.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("tracing: resource creation: %w", err)
	}

	var exp sdktrace.SpanExporter
	if cfg.Endpoint != "" {
		traceOptions := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
			otlptracegrpc.WithDialOption(grpc.WithBlock()),
			otlptracegrpc.WithTimeout(timeoutOrDefault(cfg.Timeout)),
		}
		if cfg.Insecure {
			traceOptions = append(traceOptions, otlptracegrpc.WithDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		} else if cfg.TLSConfig != nil {
			traceOptions = append(traceOptions, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(cfg.TLSConfig)))
		}
		if len(cfg.Headers) > 0 {
			headers := make(map[string]string, len(cfg.Headers))
			for k, v := range cfg.Headers {
				headers[k] = v
			}
			traceOptions = append(traceOptions, otlptracegrpc.WithHeaders(headers))
		}
		exp, err = otlptracegrpc.New(ctx, traceOptions...)
		if err != nil {
			return nil, fmt.Errorf("tracing: exporter: %w", err)
		}
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.SampleRatio > 0 && cfg.SampleRatio < 1 {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}

	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	}
	if exp != nil {
		tpOpts = append(tpOpts, sdktrace.WithBatcher(exp))
	}

	provider := sdktrace.NewTracerProvider(tpOpts...)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	shutdown := func(ctx context.Context) error {
		if err := provider.Shutdown(ctx); err != nil {
			return fmt.Errorf("tracing: provider shutdown: %w", err)
		}
		return nil
	}

	return &Provider{
		TracerProvider: provider,
		shutdown:       shutdown,
	}, nil
}

// Tracer returns a named tracer.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// Shutdown flushes and tears down the pipeline.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

func timeoutOrDefault(val time.Duration) time.Duration {
	if val <= 0 {
		return 5 * time.Second
	}
	return val
}

func buildVersion() string {
	if v := os.Getenv("BUILD_VERSION"); v != "" {
		return v
	}
	return "dev"
}
