package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"runtime/trace"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/gmon/ebpf"
	"github.com/keisku/gmon/kernel"
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/prometheusexporter"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
)

var (
	level = flag.String(
		"level",
		slog.LevelInfo.String(),
		fmt.Sprintf("log level could be one of %q",
			[]slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError},
		))
	levelMap = map[string]slog.Level{
		"DEBUG": slog.LevelDebug,
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		"info":  slog.LevelInfo,
		"WARN":  slog.LevelWarn,
		"warn":  slog.LevelWarn,
		"ERROR": slog.LevelError,
		"error": slog.LevelError,
	}
	pid          = flag.Int("pid", 0, "Useful when tracing programs that have many running instances")
	binPath      = flag.String("path", "", "Path to executable file to be monitored (required)")
	traceOutPath = flag.String("trace", "/tmp/gmon-trace.out", "File path to trace output")
	pprofPort    = flag.Int("pprof", 0, "Port to be used for pprof server. If 0, pprof server is not started")
	metricsPort  = flag.Int("metrics", 5500, "Port to be used for metrics server, /metrics endpoint")
)

func main() {
	flag.Parse()
	opts := &slog.HandlerOptions{Level: levelMap[*level]}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
	errlog := log.New(os.Stderr, "", log.LstdFlags)
	prometheusexporterLogger, _ := zap.NewProduction()

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("gmon only works on amd64 Linux")
	}

	traceOutFile, err := os.Create(*traceOutPath)
	if err != nil {
		errlog.Fatalln(err)
	}
	if err := trace.Start(traceOutFile); err != nil {
		errlog.Fatalln(err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	meterProvider := metric.NewMeterProvider()
	otel.SetMeterProvider(meterProvider)
	prometheusexporterFactory := prometheusexporter.NewFactory()
	metricsExporter, err := prometheusexporterFactory.CreateMetricsExporter(
		ctx,
		exporter.CreateSettings{
			ID: component.NewID(component.DataTypeMetrics),
			TelemetrySettings: component.TelemetrySettings{
				Logger:         prometheusexporterLogger,
				MeterProvider:  meterProvider,
				TracerProvider: noop.NewTracerProvider(),
			},
			BuildInfo: component.BuildInfo{
				Command:     "gmon",
				Description: "Goroutine monitor for Go programs",
				Version:     "0.0.0-dev",
			},
		},
		&prometheusexporter.Config{
			HTTPServerSettings: confighttp.HTTPServerSettings{
				Endpoint: fmt.Sprintf("127.0.0.1:%d", *metricsPort),
			},
			Namespace:         "gmon",
			EnableOpenMetrics: true,
			MetricExpiration:  time.Minute,
		},
	)
	if err != nil {
		errlog.Fatalln(fmt.Errorf("create prometheus exporter: %w", err))
	}
	if err := metricsExporter.Start(ctx, nil); err != nil {
		errlog.Fatalln(fmt.Errorf("start prometheus exporter: %w", err))
	}
	metricsQueue := make(chan pmetric.Metrics, 50)
	go func() {
		for ms := range metricsQueue {
			if err := metricsExporter.ConsumeMetrics(ctx, ms); err != nil {
				slog.Warn("consume metrics", slog.Any("error", err))
			}
		}
	}()

	ebpfConfig, err := ebpf.NewConfig(
		*binPath,
		*pid,
		metricsQueue,
	)
	if err != nil {
		errlog.Fatalln(err)
	}
	eBPFClose, err := ebpf.Run(ctx, ebpfConfig)
	if err != nil {
		errlog.Fatalln(err)
	}
	slog.Debug(
		"gmon starts",
		slog.String("binary_path", *binPath),
		slog.String("kernel_release", kernel.Release()),
	)
	if 1023 < *pprofPort {
		go func() {
			_ = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", pprofPort), nil)
		}()
	}
	<-ctx.Done()
	slog.Debug("gmon exits")
	close(metricsQueue)
	metricsExporter.Shutdown(context.Background())
	eBPFClose()
}
