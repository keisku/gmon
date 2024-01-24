package ebpf

import (
	"bufio"
	"context"
	"debug/elf"
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
	"github.com/keisku/gmon/addr2line"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target amd64 -cflags $BPF_CFLAGS bpf ./c/gmon.c -- -I./c

// maxStackDepth is the max depth of each stack trace to track
// Matches 'MAX_STACK_DEPTH' in eBPF code
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

func Run(ctx context.Context, config Config) (context.CancelFunc, error) {
	slog.Debug("eBPF programs start with config", slog.String("config", config.String()))
	wrappedCtx, cancel := context.WithCancel(ctx)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return cancel, err
	}
	go logTracePipe(wrappedCtx.Done())
	elfFile, err := elf.Open(config.binPath)
	if err != nil {
		return cancel, err
	}
	if err := addr2line.Init(elfFile); err != nil {
		slog.Debug("initialize addr2line", slog.Any("err", err))
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
				processNewproc1Events(&objs, goroutineQueue)
				processGoexit1Events(&objs, goroutineQueue)
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

func processNewproc1Events(objs *bpfObjects, goroutineQueue chan<- goroutine) error {
	var key bpfNewproc1EventKey
	var value bpfNewproc1Event
	var keysToDelete []bpfNewproc1EventKey

	return processEvents(
		objs.StackAddresses,
		objs.Newproc1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				goroutineQueue <- goroutine{
					Id:         key.GoroutineId,
					ObservedAt: time.Now(),
					Stack:      stack,
					Exit:       false,
				}
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processGoexit1Events(objs *bpfObjects, goroutineQueue chan<- goroutine) error {
	var key bpfGoexit1EventKey
	var value bpfGoexit1Event
	var keysToDelete []bpfGoexit1EventKey

	return processEvents(
		objs.StackAddresses,
		objs.Goexit1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := extractStack(objs, value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				goroutineQueue <- goroutine{
					Id:         key.GoroutineId,
					ObservedAt: time.Now(),
					Stack:      stack,
					Exit:       true,
				}
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func processEvents(
	stackAddrs, eventMap *ebpf.Map,
	// stackIdSet is the set of stack_id to delete later.
	// keysToDelete is the slice of eBPF map keys to delete later.
	// keyLength holds the count of keys in keysToDelete to determine if BatchDelete is required.
	processMap func(iter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (keysToDelete any, keyLength int),
) error {
	stackIdSetToDelete := make(map[int32]struct{})
	mapIter := eventMap.Iterate()
	keysToDelete, keyLength := processMap(mapIter, stackIdSetToDelete)
	if err := mapIter.Err(); err != nil {
		return fmt.Errorf("failed to iterate eBPF map: %w", err)
	}
	if 0 < keyLength {
		if n, err := eventMap.BatchDelete(keysToDelete, nil); err == nil {
			slog.Debug("Deleted eBPF map", slog.Int("deleted", n), slog.Int("expected", keyLength))
		} else {
			slog.Warn("Failed to delete eBPF map", slog.String("error", err.Error()))
		}
	}
	// Don't use BatchDelete for stack addresses because the opration is not supported.
	// If we do it, we will see "batch delete: not supported" error.
	for stackId := range stackIdSetToDelete {
		if err := stackAddrs.Delete(stackId); err != nil {
			slog.Warn("Failed to delete stack_addresses", slog.String("error", err.Error()))
			continue
		}
		slog.Debug("Deleted stack address map", slog.Int("stack_id", int(stackId)))
	}
	return nil
}

func extractStack(objs *bpfObjects, stackId int32) (addr2line.Stack, error) {
	stack := make(addr2line.Stack, maxStackDepth)
	stackBytes, err := objs.StackAddresses.LookupBytes(stackId)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup stack address: %w", err)
	}
	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackBytes[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		stack[stackCounter] = addr2line.Do(stackAddr)
		stackCounter++
	}
	return stack[0:stackCounter], nil
}

func stackToLogAttr(stack []string) slog.Attr {
	attrs := make([]slog.Attr, len(stack))
	for i, s := range stack {
		attrs[i] = slog.String(fmt.Sprintf("%d", i), s)
	}
	return slog.Attr{
		Key:   "stack",
		Value: slog.GroupValue(attrs...),
	}
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
