package ebpf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/keisku/gmon/bininfo"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target amd64 -cflags $BPF_CFLAGS bpf ./c/gmon.c -- -I./c

func Run(ctx context.Context, config Config) (func(), error) {
	slog.Debug("eBPF programs start with config", slog.String("config", config.String()))
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return func() {}, err
	}
	biTranslator, err := bininfo.NewTranslator(config.binPath)
	if err != nil {
		return func() {}, err
	}
	go logTracePipe(ctx.Done())
	ex, err := link.OpenExecutable(config.binPath)
	if err != nil {
		return func() {}, err
	}
	var links [2]link.Link
	links[0], err = linkUprobe(
		ex,
		objs.RuntimeNewproc1,
		"runtime.newproc1",
		true,
		config.pid,
		biTranslator.Address,
	)
	if err != nil {
		return func() {}, err
	}
	links[1], err = linkUprobe(
		ex,
		objs.RuntimeGoexit1,
		"runtime.goexit1",
		false,
		config.pid,
		biTranslator.Address,
	)
	if err != nil {
		return func() {}, err
	}
	goroutineQueue := make(chan goroutine, 100)
	eventhandler := &eventHandler{
		goroutineQueue: goroutineQueue,
		objs:           &objs,
		biTranslator:   biTranslator,
	}
	reporter := &reporter{
		goroutineQueue: goroutineQueue,
	}
	go reporter.run(ctx)
	go eventhandler.run(ctx)
	return func() {
		for i := range links {
			if err := links[i].Close(); err != nil {
				slog.Warn("Failed to close link", slog.Any("error", err))
			}
		}
		if err := objs.Close(); err != nil {
			slog.Warn("Failed to close bpf objects: %s", err)
		}
	}, nil
}

func linkUprobe(
	exe *link.Executable,
	program *ebpf.Program,
	symbol string,
	ret bool,
	pid int,
	lookupAddress func(string) uint64,
) (link.Link, error) {
	var l link.Link
	var err error
	if ret {
		l, err = exe.Uretprobe(symbol, program, &link.UprobeOptions{PID: pid})
	} else {
		l, err = exe.Uprobe(symbol, program, &link.UprobeOptions{PID: pid})
	}
	if err == nil {
		return l, nil
	}
	if errors.Is(err, link.ErrNoSymbol) {
		slog.Debug("no symbol table", slog.String("symbol", symbol))
	} else {
		return nil, fmt.Errorf("failed to attach uprobe for %s: %w", symbol, err)
	}
	address := lookupAddress(symbol)
	if address == 0 {
		return nil, fmt.Errorf("no address found for %s", symbol)
	}
	if ret {
		l, err = exe.Uretprobe(symbol, program, &link.UprobeOptions{PID: pid, Address: address})
	} else {
		l, err = exe.Uprobe(symbol, program, &link.UprobeOptions{PID: pid, Address: address})
	}
	if err != nil {
		return nil, fmt.Errorf("failed to attach uprobe for %s: %w", symbol, err)
	}
	slog.Debug("attach uprobe with address", slog.String("symbol", symbol), slog.String("address", fmt.Sprintf("%#x", address)))
	return l, nil
}

func logTracePipe(done <-chan struct{}) {
	tracePipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		slog.Error("open trace_pipe", slog.Any("error", err))
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
				slog.Warn(msg)
			}
		}
		if err := scanner.Err(); err != nil {
			if !errors.Is(err, fs.ErrClosed) {
				slog.Error("read trace_pipe", slog.Any("error", err))
			}
		}
	}()
	<-done
}
