package main

import (
	"context"
	"debug/buildinfo"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/keisku/gmon/ebpf"
	"github.com/keisku/gmon/kernel"
)

var level slog.Level
var pid int
var binPath string
var pprofPort int
var uptimeDebug string
var uptimeInfo string
var uptimeWarn string
var uptimeError string

func main() {
	errlog := log.New(os.Stderr, "", log.LstdFlags)

	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		errlog.Fatalln("gmon only works on amd64 Linux")
	}

	flag.StringVar(&binPath, "path", binPath, "Path to executable file to be monitored (required)")
	flag.TextVar(&level, "level", level, fmt.Sprintf("log level could be one of %q",
		[]slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}))
	flag.IntVar(&pid, "pid", pid, "Useful when tracing programs that have many running instances")
	flag.IntVar(&pprofPort, "pprof-port", pprofPort, "Port to be used for pprof server")
	uptimeHelpFmt := `Uptime threshold for %s level log. E.g., "0", "100ms", "1s500ms". See https://pkg.go.dev/time#ParseDuration`
	flag.StringVar(&uptimeDebug, "uptime-debug", "0", fmt.Sprintf(uptimeHelpFmt, "debug"))
	flag.StringVar(&uptimeInfo, "uptime-info", "1s", fmt.Sprintf(uptimeHelpFmt, "info"))
	flag.StringVar(&uptimeWarn, "uptime-warn", "10s", fmt.Sprintf(uptimeHelpFmt, "warn"))
	flag.StringVar(&uptimeError, "uptime-error", "1m", fmt.Sprintf(uptimeHelpFmt, "error"))
	flag.Parse()
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := rlimit.RemoveMemlock(); err != nil {
		errlog.Fatalln(err)
	}

	ebpfConfig, err := ebpf.NewConfig(
		binPath,
		pid,
		uptimeDebug,
		uptimeInfo,
		uptimeWarn,
		uptimeError,
	)
	if err != nil {
		errlog.Fatalln(err)
	}
	eBPFClose, err := ebpf.Run(ctx, ebpfConfig)
	if err != nil {
		errlog.Fatalln(err)
	}
	buildinfoAttrs, err := loadBuildinfo(binPath)
	if err != nil {
		slog.Debug(err.Error())
	}
	slog.Debug(
		"gmon starts",
		slog.String("binary_path", binPath),
		slog.String("kernel_release", kernel.Release()),
		buildinfoAttrs,
	)
	if 1023 < pprofPort {
		go func() {
			_ = http.ListenAndServe(fmt.Sprintf("localhost:%d", pprofPort), nil)
		}()
	}

	<-ctx.Done()
	slog.Debug("gmon exits")
	eBPFClose()
}

func loadBuildinfo(binPath string) (slog.Attr, error) {
	debugBuildinfo, err := buildinfo.ReadFile(binPath)
	if err != nil {
		return slog.Attr{}, fmt.Errorf("read buildinfo: %w", err)
	}
	args := []any{"version", debugBuildinfo.GoVersion}
	for _, s := range debugBuildinfo.Settings {
		if s.Value == "" {
			continue
		}
		key := s.Key
		if strings.HasPrefix(s.Key, "-") {
			key = strings.TrimPrefix(key, "-")
		}
		args = append(args, []any{key, s.Value}...)
	}
	return slog.Group("buildinfo", args...), nil
}
