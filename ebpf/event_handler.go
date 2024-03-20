package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"runtime/trace"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/keisku/gmon/bininfo"
)

type eventHandler struct {
	goroutineQueue chan<- goroutine
	objs           *bpfObjects
	biTranslator   bininfo.Translator
}

func (h *eventHandler) run(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			ctx, task := trace.NewTask(ctx, "event_handler.handle")
			trace.WithRegion(ctx, "event_handler.handle_newproc1", func() {
				if err := h.handleNewproc1(); err != nil {
					slog.Warn("Failed to handle newproc1", slog.Any("error", err))
				}
			})
			trace.WithRegion(ctx, "event_handler.handle_goexit1", func() {
				if err := h.handleGoexit1(); err != nil {
					slog.Warn("Failed to handle goexit1", slog.Any("error", err))
				}
			})
			task.End()
		}
	}
}

// lookupStack is a copy of the function in tracee.
// https://github.com/aquasecurity/tracee/blob/f61866b4e2277d2a7dddc6cd77a67cd5a5da3b14/pkg/ebpf/events_pipeline.go#L642-L681
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

func (h *eventHandler) lookupStack(stackId int32) ([]*proc.Function, error) {
	stackBytes, err := h.objs.StackAddresses.LookupBytes(stackId)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup stack addresses: %w", err)
	}
	if stackBytes == nil {
		return nil, fmt.Errorf("bytes not found by stack_id=%d", stackId)
	}
	stack := make([]*proc.Function, maxStackDepth)
	stackCounter := 0
	for i := 0; i < len(stackBytes); i += stackFrameSize {
		stackBytes[stackCounter] = 0
		stackAddr := binary.LittleEndian.Uint64(stackBytes[i : i+stackFrameSize])
		if stackAddr == 0 {
			break
		}
		f := h.biTranslator.PCToFunc(stackAddr)
		if f == nil {
			// I don't know why, but a function address sometime should be last 3 bytes.
			// At leaset, I observerd this behavior in the following binaries:
			// - /usr/bin/dockerd
			// - /usr/bin/containerd
			f = h.biTranslator.PCToFunc(stackAddr & 0xffffff)
			if f == nil {
				f = &proc.Function{Name: fmt.Sprintf("%#x", stackAddr), Entry: stackAddr}
			}
		}
		stack[stackCounter] = f
		stackCounter++
	}
	return stack[0:stackCounter], nil
}

func (h *eventHandler) handle(
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
			slog.Warn("Failed to delete eBPF map", slog.Any("err", err))
		}
	}
	// Don't use BatchDelete for stack addresses because the opration is not supported.
	// If we do it, we will see "batch delete: not supported" error.
	for stackId := range stackIdSetToDelete {
		if err := stackAddrs.Delete(stackId); err != nil {
			slog.Debug("Failed to delete stack_addresses", slog.Any("error", err))
			continue
		}
		slog.Debug("Deleted stack address map", slog.Int("stack_id", int(stackId)))
	}
	return nil
}

func (h *eventHandler) sendGoroutine(g goroutine) {
	maxRetries := 3
	retryInterval := 10 * time.Millisecond
	for attempts := 0; attempts < maxRetries; attempts++ {
		select {
		case h.goroutineQueue <- g:
			if attempts > 0 {
				slog.Info(
					"goroutine is sent successfully after retries",
					slog.Int("retry", attempts+1),
					slog.String("goroutine_id", fmt.Sprintf("%d", g.Id)),
					slog.Bool("exit", g.Exit),
					stackLogAttr(g.Stack),
				)
			}
			return // Successfully sent
		default:
			if attempts < maxRetries-1 {
				time.Sleep(retryInterval) // Wait before retrying
			} else {
				slog.Warn(
					"goroutine queue is full, retrying",
					slog.String("goroutine_id", fmt.Sprintf("%d", g.Id)),
					slog.Bool("exit", g.Exit),
					stackLogAttr(g.Stack),
				)
			}
		}
	}
}

func (h *eventHandler) handleNewproc1() error {
	var key bpfNewproc1EventKey
	var value bpfNewproc1Event
	var keysToDelete []bpfNewproc1EventKey

	return h.handle(
		h.objs.StackAddresses,
		h.objs.Newproc1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := h.lookupStack(value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				h.sendGoroutine(goroutine{
					Id:         key.GoroutineId,
					ObservedAt: time.Now(),
					Stack:      stack,
					Exit:       false,
				})
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}

func (h *eventHandler) handleGoexit1() error {
	var key bpfGoexit1EventKey
	var value bpfGoexit1Event
	var keysToDelete []bpfGoexit1EventKey

	return h.handle(
		h.objs.StackAddresses,
		h.objs.Goexit1Events,
		func(mapIter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (any, int) {
			for mapIter.Next(&key, &value) {
				stack, err := h.lookupStack(value.StackId)
				if err != nil {
					slog.Warn(err.Error())
					continue
				}
				stackIdSet[value.StackId] = struct{}{}
				keysToDelete = append(keysToDelete, key)
				h.sendGoroutine(goroutine{
					Id:         key.GoroutineId,
					ObservedAt: time.Now(),
					Stack:      stack,
					Exit:       false,
				})
			}
			return keysToDelete, len(keysToDelete)
		},
	)
}
