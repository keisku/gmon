package ebpf

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/keisku/gmon/bininfo"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target amd64 -cflags $BPF_CFLAGS bpf ./c/gmon.c -- -I./c

func Run(ctx context.Context, config Config) (context.CancelFunc, error) {
	slog.Debug("eBPF programs start with config", slog.String("config", config.String()))
	wrappedCtx, cancel := context.WithCancel(ctx)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return cancel, err
	}
	go logTracePipe(wrappedCtx.Done())
	bininfo, err := bininfo.NewBinInfo(config.binPath)
	if err != nil {
		return cancel, err
	}
	ex, err := link.OpenExecutable(config.binPath)
	if err != nil {
		return cancel, err
	}
	type uprobeArguments struct {
		symbol string
		prog   *ebpf.Program
		opts   *link.UprobeOptions
		ret    bool
	}
	uprobeArgs := []uprobeArguments{
		{"runtime.newproc1", objs.RuntimeNewproc1, uprobeOptions(config.pid), true},
		{"runtime.goexit1", objs.RuntimeGoexit1, uprobeOptions(config.pid), false},
	}
	uprobeLinks := make([]link.Link, 0, len(uprobeArgs))
	for i := 0; i < len(uprobeArgs); i++ {
		var link link.Link
		var err error
		if uprobeArgs[i].ret {
			link, err = ex.Uretprobe(uprobeArgs[i].symbol, uprobeArgs[i].prog, uprobeArgs[i].opts)
		} else {
			link, err = ex.Uprobe(uprobeArgs[i].symbol, uprobeArgs[i].prog, uprobeArgs[i].opts)
		}
		if err != nil {
			slog.Debug(err.Error())
			continue
		}
		uprobeLinks = append(uprobeLinks, link)
	}
	if len(uprobeLinks) == 0 {
		return cancel, errors.New("no uprobe links")
	}
	goroutineQueue := make(chan goroutine)
	eventhandler := &eventHandler{
		goroutineQueue: goroutineQueue,
		objs:           &objs,
		bininfo:        bininfo,
	}
	reporter := &reporter{
		goroutineQueue:         goroutineQueue,
		uptimeThreshold:        config.uptimeThreshold,
		monitorExpiryThreshold: config.monitorExpiryThreshold,
	}
	go reporter.run(wrappedCtx)
	go func() {
		for {
			select {
			case <-wrappedCtx.Done():
				slog.Debug("eBPF programs stop")
				return
			case <-time.Tick(200 * time.Millisecond):
				eventhandler.handleNewproc1()
				eventhandler.handleGoexit1()
			}
		}
	}()
	return func() {
		// Don't use for-range to avoid copying the slice.
		for i := 0; i < len(uprobeLinks); i++ {
			if err := uprobeLinks[i].Close(); err != nil {
				slog.Warn(err.Error())
			}
		}
		if err := objs.Close(); err != nil {
			slog.Warn("Failed to close bpf objects: %s", err)
		}
		cancel()
	}, nil
}

func uprobeOptions(pid int) *link.UprobeOptions {
	if 0 < pid {
		return &link.UprobeOptions{PID: pid}
	}
	return nil
}

func logTracePipe(done <-chan struct{}) {
	tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		slog.Error("open trace_pipe", slog.String("error", err.Error()))
		return
	}
	defer tracePipe.Close()

	go func() {
		// Create a bufio.Scanner to read the trace data.
		scanner := bufio.NewScanner(tracePipe)
		// Read and print the trace data.
		for scanner.Scan() {
			msg := strings.TrimSpace(scanner.Text())
			if strings.Contains(msg, "gmon") {
				slog.Debug(msg)
			}
		}
		if err := scanner.Err(); err != nil {
			if !errors.Is(err, fs.ErrClosed) {
				slog.Error("read trace_pipe", slog.String("error", err.Error()))
			}
		}
	}()
	<-done
}
