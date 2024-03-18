package ebpf

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/go-delve/delve/pkg/proc"
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
	_, err = linkUprobe(
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
	_, err = linkUprobe(
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
	// lookupStack is a copy of the function in tracee.
	// https://github.com/aquasecurity/tracee/blob/f61866b4e2277d2a7dddc6cd77a67cd5a5da3b14/pkg/ebpf/events_pipeline.go#L642-L681
	const maxStackDepth = 20
	var stackFrameSize = (strconv.IntSize / 8)
	eventhandler := &eventHandler{
		goroutineQueue: goroutineQueue,
		objs:           &objs,
		lookupStack: func(id int32) ([]*proc.Function, error) {
			stackBytes, err := objs.StackAddresses.LookupBytes(id)
			if err != nil {
				return nil, fmt.Errorf("failed to lookup stack address: %w", err)
			}
			stack := make([]*proc.Function, maxStackDepth)
			stackCounter := 0
			for i := 0; i < len(stackBytes); i += stackFrameSize {
				stackBytes[stackCounter] = 0
				stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
				if stackAddr == 0 {
					break
				}
				f := biTranslator.PCToFunc(stackAddr)
				if f == nil {
					// I don't know why, but a function address sometime should be last 3 bytes.
					// At leaset, I observerd this behavior in the following binaries:
					// - /usr/bin/dockerd
					// - /usr/bin/containerd
					f = biTranslator.PCToFunc(stackAddr & 0xffffff)
					if f == nil {
						f = &proc.Function{Name: fmt.Sprintf("%#x", stackAddr), Entry: stackAddr}
					}
				}
				stack[stackCounter] = f
				stackCounter++
			}
			return stack[0:stackCounter], nil
		},
	}
	reporter := &reporter{
		goroutineQueue: goroutineQueue,
		metircsQueue:   config.metricsQueue,
	}
	go reporter.run(ctx)
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				slog.Debug("eBPF programs stop")
				ticker.Stop()
				return
			case <-ticker.C:
				eventhandler.handleNewproc1(ctx)
				eventhandler.handleGoexit1(ctx)
			}
		}
	}()
	return func() {
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
				slog.Warn(msg)
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
