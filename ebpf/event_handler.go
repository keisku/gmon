package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"runtime/trace"
	"strconv"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/go-delve/delve/pkg/proc"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/keisku/gmon/bininfo"
)

type eventHandler struct {
	goroutineQueue chan<- goroutine
	objs           *bpfObjects
	biTranslator   bininfo.Translator
	reader         *ringbuf.Reader
}

func (h *eventHandler) run(ctx context.Context) {
	var event bpfEvent
	// To delete stack_addresses that is not used recently.
	stackIdCache := expirable.NewLRU[int32, struct{}](
		32, // cache size
		func(key int32, _ struct{}) {
			slog.Debug("delete stack_addresses", slog.Int("stack_id", int(key)))
			if err := h.objs.StackAddresses.Delete(key); err != nil {
				slog.Debug("Failed to delete stack_addresses", slog.Any("error", err))
			}
		},
		time.Minute, // TTL of each cache entry
	)
	for {
		if err := h.readRecord(ctx, &event); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Debug("ring buffer is closed")
				return
			}
			slog.Warn("Failed to read bpf ring buffer", slog.Any("error", err))
			continue
		}
		stack, err := h.lookupStack(ctx, event.StackId)
		if err != nil {
			slog.Warn(err.Error())
			continue
		}
		h.sendGoroutine(goroutine{
			Id:         event.GoroutineId,
			ObservedAt: time.Now(),
			Stack:      stack,
			Exit:       event.Exit,
		})
		_ = stackIdCache.Add(event.StackId, struct{}{})
	}
}

func (h *eventHandler) readRecord(ctx context.Context, event *bpfEvent) error {
	_, task := trace.NewTask(ctx, "event_handler.read_ring_buffer")
	defer task.End()
	record, err := h.reader.Read()
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, event); err != nil {
		return fmt.Errorf("decode ring buffer record: %w", err)
	}
	return nil
}

// lookupStack is a copy of the function in tracee.
// https://github.com/aquasecurity/tracee/blob/f61866b4e2277d2a7dddc6cd77a67cd5a5da3b14/pkg/ebpf/events_pipeline.go#L642-L681
const maxStackDepth = 20

var stackFrameSize = (strconv.IntSize / 8)

func (h *eventHandler) lookupStack(ctx context.Context, stackId int32) ([]*proc.Function, error) {
	_, task := trace.NewTask(ctx, "event_handler.lookup_stack")
	defer task.End()
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
