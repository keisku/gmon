package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/keisku/gmon/addr2line"
)

type goroutine struct {
	Id         int64
	ObservedAt time.Time
	Stack      addr2line.Stack
	Exit       bool
}

type reporter struct {
	goroutineQueue         <-chan goroutine
	goroutineMap           sync.Map
	uptimeThreshold        time.Duration
	monitorExpiryThreshold time.Duration
}

func (r *reporter) run(ctx context.Context) {
	go func() {
		for range time.Tick(time.Second) {
			if err := ctx.Err(); err != nil {
				return
			}
			r.reportGoroutineUptime()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case g, ok := <-r.goroutineQueue:
			if !ok {
				slog.Debug("goroutineQueue closed")
				return
			}
			r.storeGoroutine(g)
		}
	}
}

func (r *reporter) reportGoroutineUptime() {
	r.goroutineMap.Range(func(_, value any) bool {
		g := value.(goroutine)
		uptime := time.Since(g.ObservedAt)
		// TODO: Report gauge metrics.
		attrs := []any{
			slog.Duration("uptime", uptime),
			slog.Int64("goroutine_id", g.Id),
			g.Stack.LogAttr(),
		}
		if uptime > r.uptimeThreshold {
			slog.Info("goroutine is running", attrs...)
		}
		if r.monitorExpiryThreshold > 0 && uptime > r.monitorExpiryThreshold {
			slog.Info(fmt.Sprintf("goroutine is still running after %s, then remove it from the monitoring targets", r.monitorExpiryThreshold), attrs...)
			r.goroutineMap.Delete(g.Id)
		}
		return true
	})
}

func (r *reporter) storeGoroutine(g goroutine) {
	v, loaded := r.goroutineMap.Load(g.Id)
	if loaded {
		oldg := v.(goroutine)
		uptime := time.Since(oldg.ObservedAt)
		attrs := []any{
			slog.Duration("uptime", uptime),
			slog.Int64("goroutine_id", g.Id),
			// Don't use g.Stack since goexit1 doesn't have informative stack.
			oldg.Stack.LogAttr(),
		}
		if uptime > r.uptimeThreshold {
			slog.Info("goroutine is terminated", attrs...)
		}
		r.goroutineMap.Delete(oldg.Id)
		return
	}
	if g.Exit {
		// Avoid storing goroutines that lack a corresponding newproc1 pair.
		return
	}
	r.goroutineMap.Store(g.Id, g)
}
