// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package otelx

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	httpTraceProtocol = "http/protobuf"
	grpcTraceProtocol = "grpc"
)

// Returns the identifier of the otlp-protocol to use. Fetches in the following order:
//  1. Protocol is explicitly specified in the config
//  2. Protocol is in OTEL_EXPORTER_OTLP_TRACES_PROTOCOL env variable
//  3. Protocol is in OTEL_EXPORTER_OTLP_PROTOCOL
//
// If all are empty, the default value `httpTraceProtocol` is returned.
func otlpExportProtocol(c *Config) string {
	if c.Providers.OTLP.Protocol != "" {
		return c.Providers.OTLP.Protocol
	}

	if p, exists := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"); exists {
		return p
	}
	if p, exists := os.LookupEnv("OTEL_EXPORTER_OTLP_PROTOCOL"); exists {
		return p
	}

	return httpTraceProtocol
}

func SetupOTLP(t *Tracer, tracerName string, c *Config) (trace.Tracer, error) {
	ctx := context.Background()

	var exp *otlptrace.Exporter
	var err error

	expProt := otlpExportProtocol(c)
	switch expProt {
	case httpTraceProtocol:
		exp, err = otlptrace.New(ctx, otlptracehttp.NewClient(httpClientOpts(c)...))
	case grpcTraceProtocol:
		exp, err = otlptrace.New(ctx, otlptracegrpc.NewClient(grpcClientOpts(c)...))
	default:
		err = fmt.Errorf("unsupported otlp export protocol: %v", expProt)
	}

	if err != nil {
		return nil, err
	}

	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(c.ServiceName),
		)),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(
			c.Providers.OTLP.Sampling.SamplingRatio,
		))),
	}

	tp := sdktrace.NewTracerProvider(tpOpts...)
	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Tracer(tracerName), nil
}

func httpClientOpts(c *Config) []otlptracehttp.Option {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(c.Providers.OTLP.ServerURL),
	}

	if c.Providers.OTLP.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	return opts
}

func grpcClientOpts(c *Config) []otlptracegrpc.Option {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(c.Providers.OTLP.ServerURL),
	}

	if c.Providers.OTLP.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	return opts
}
