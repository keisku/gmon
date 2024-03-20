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

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/gmon/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	traceOutPath = flag.String("trace", "", "Path to Go runtime/trace output")
	pprofPort    = flag.Int("pprof", 0, "Port to be used for pprof server. If 0, pprof server is not started")
	metricsPort  = flag.Int("metrics", 5500, "Port to be used for metrics server, /metrics endpoint")
)

type promLogger struct{}

func (promLogger) Println(v ...interface{}) {
	slog.Error(fmt.Sprint(v...))
}

func main() {
	flag.Parse()
	opts := &slog.HandlerOptions{Level: levelMap[*level]}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
	errlog := log.New(os.Stderr, "", log.LstdFlags)

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("gmon only works on amd64 Linux")
	}

	if *traceOutPath != "" {
		traceOutFile, err := os.Create(*traceOutPath)
		if err != nil {
			errlog.Fatalln(err)
		}
		if err := trace.Start(traceOutFile); err != nil {
			errlog.Fatalln(err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	http.Handle("/metrics", promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			ErrorLog:          promLogger{},
			EnableOpenMetrics: true,
		},
	))
	go http.ListenAndServe(fmt.Sprintf(":%d", *metricsPort), nil)

	ebpfConfig, err := ebpf.NewConfig(
		*binPath,
		*pid,
	)
	if err != nil {
		errlog.Fatalln(err)
	}
	eBPFClose, err := ebpf.Run(ctx, ebpfConfig)
	if err != nil {
		errlog.Fatalln(err)
	}
	if 1023 < *pprofPort {
		go func() {
			_ = http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", pprofPort), nil)
		}()
	}
	<-ctx.Done()
	slog.Debug("gmon exits")
	eBPFClose()
}
