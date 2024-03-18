package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/trace"
	"time"

	"github.com/cilium/ebpf"
	"github.com/go-delve/delve/pkg/proc"
)

type eventHandler struct {
	lookupStack    func(int32) ([]*proc.Function, error)
	goroutineQueue chan<- goroutine
	objs           *bpfObjects
}

func (h *eventHandler) handle(
	ctx context.Context,
	stackAddrs, eventMap *ebpf.Map,
	// stackIdSet is the set of stack_id to delete later.
	// keysToDelete is the slice of eBPF map keys to delete later.
	// keyLength holds the count of keys in keysToDelete to determine if BatchDelete is required.
	processMap func(iter *ebpf.MapIterator, stackIdSet map[int32]struct{}) (keysToDelete any, keyLength int),
) error {
	defer trace.StartRegion(ctx, "event_handler.handle").End()

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
					slog.String("top_frame", g.topFrame()),
					slog.Bool("exit", g.Exit),
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
					slog.String("top_frame", g.topFrame()),
					slog.Bool("exit", g.Exit),
				)
			}
		}
	}
}

func (h *eventHandler) handleNewproc1(ctx context.Context) error {
	ctx, task := trace.NewTask(ctx, "event_handler.handle_newproc1")
	defer task.End()

	var key bpfNewproc1EventKey
	var value bpfNewproc1Event
	var keysToDelete []bpfNewproc1EventKey

	return h.handle(
		ctx,
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

func (h *eventHandler) handleGoexit1(ctx context.Context) error {
	ctx, task := trace.NewTask(ctx, "event_handler.handle_goexit1")
	defer task.End()

	var key bpfGoexit1EventKey
	var value bpfGoexit1Event
	var keysToDelete []bpfGoexit1EventKey

	return h.handle(
		ctx,
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
