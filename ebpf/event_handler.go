package ebpf

import (
	"fmt"
	"log/slog"
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

func (h *eventHandler) sendGoroutine(g goroutine) {
	select {
	case h.goroutineQueue <- g:
	default:
		slog.Warn(
			"goroutine queue is full, dropping goroutine",
			slog.String("goroutine_id", fmt.Sprintf("%d", g.Id)),
			slog.String("top_frame", fmt.Sprintf("%s", g.topFrame())),
		)
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
