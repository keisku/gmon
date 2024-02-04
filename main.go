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

var level slog.Level
var pid int
var binPath string
var pprofPort int
var metricsPort int = 5500
var monitorExpiryThreshold string

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)
	prometheusexporterLogger, _ := zap.NewProduction()

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("gmon only works on amd64 Linux")
	}

	flag.StringVar(&binPath, "path", binPath, "Path to executable file to be monitored (required)")
	flag.TextVar(&level, "level", level, fmt.Sprintf("log level could be one of %q",
		[]slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}))
	flag.IntVar(&pid, "pid", pid, "Useful when tracing programs that have many running instances")
	flag.IntVar(&pprofPort, "pprof-port", pprofPort, "Port to be used for pprof server")
	flag.IntVar(&metricsPort, "metrics-port", metricsPort, "Port to be used for metrics server, /metrics endpoint")
	durationHelpFmt := `%s E.g., "0", "100ms", "1s500ms". See https://pkg.go.dev/time#ParseDuration`
	flag.StringVar(&monitorExpiryThreshold, "monitor-expiry-threshold", "0", fmt.Sprintf(durationHelpFmt, "Remove a goroutine from monitoring when its uptime exceeds this value. If set to 0, the goroutine will never be deleted."))
	flag.Parse()
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

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
				Endpoint: fmt.Sprintf("127.0.0.1:%d", metricsPort),
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
	metricsQueue := make(chan pmetric.Metrics)
	go func() {
		for ms := range metricsQueue {
			metricsExporter.ConsumeMetrics(ctx, ms)
		}
	}()

	ebpfConfig, err := ebpf.NewConfig(
		binPath,
		pid,
		monitorExpiryThreshold,
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
		slog.String("binary_path", binPath),
		slog.String("kernel_release", kernel.Release()),
	)
	if 1023 < pprofPort {
		go func() {
			_ = http.ListenAndServe(fmt.Sprintf("localhost:%d", pprofPort), nil)
		}()
	}
	<-ctx.Done()
	slog.Debug("gmon exits")
	close(metricsQueue)
	metricsExporter.Shutdown(context.Background())
	eBPFClose()
}
