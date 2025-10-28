package metrics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config governs OTLP metric exporter bootstrap.
type Config struct {
	Endpoint    string
	Insecure    bool
	ServiceName string
	Environment string
	Interval    time.Duration
	Timeout     time.Duration
	Attributes  map[string]string
}

// Provider wraps the sdk provider with a shutdown hook.
type Provider struct {
	MeterProvider *sdkmetric.MeterProvider
	shutdown      func(context.Context) error
}

// New establishes an OTLP metric pipeline and registers it globally.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ServiceName == "" {
		return nil, errors.New("metrics: service name is required")
	}

	resAttrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(cfg.ServiceName),
		semconv.ServiceVersionKey.String(buildVersion()),
		semconv.DeploymentEnvironmentKey.String(cfg.Environment),
	}
	for k, v := range cfg.Attributes {
		resAttrs = append(resAttrs, attribute.String(k, v))
	}

	res, err := resource.New(ctx, resource.WithAttributes(resAttrs...))
	if err != nil {
		return nil, fmt.Errorf("metrics: create resource: %w", err)
	}

	var exp *otlpmetricgrpc.Exporter
	if cfg.Endpoint != "" {
		dialCtx, cancel := context.WithTimeout(ctx, timeoutOrDefault(cfg.Timeout))
		defer cancel()
		options := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
			otlpmetricgrpc.WithDialOption(grpc.WithBlock()),
		}
		if cfg.Insecure {
			options = append(options, otlpmetricgrpc.WithInsecure())
		} else {
			options = append(options, otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
		}
		exp, err = otlpmetricgrpc.New(dialCtx, options...)
		if err != nil {
			return nil, fmt.Errorf("metrics: dial exporter: %w", err)
		}
	}

	options := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}
	if exp != nil {
		reader := sdkmetric.NewPeriodicReader(
			exp,
			sdkmetric.WithInterval(intervalOrDefault(cfg.Interval)),
		)
		options = append(options, sdkmetric.WithReader(reader))
	}

	provider := sdkmetric.NewMeterProvider(options...)
	otel.SetMeterProvider(provider)

	shutdown := func(ctx context.Context) error {
		if err := provider.Shutdown(ctx); err != nil {
			return fmt.Errorf("metrics: provider shutdown: %w", err)
		}
		return nil
	}

	return &Provider{
		MeterProvider: provider,
		shutdown:      shutdown,
	}, nil
}

// Meter fetches named meter from global provider.
func Meter(name string) metric.Meter {
	return otel.GetMeterProvider().Meter(name)
}

// Shutdown closes the provider gracefully.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

func intervalOrDefault(val time.Duration) time.Duration {
	if val <= 0 {
		return 15 * time.Second
	}
	return val
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
