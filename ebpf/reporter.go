package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/trace"
	"sync"
	"time"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	namespace     = "gmon"
	goroutineExit = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "goroutine_exit",
			Help:      "The number of goroutines that have been exited",
		},
		[]string{"top_frame"},
	)
	goroutineCreation = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "goroutine_creation",
			Help:      "The number of goroutines that have been creaated",
		},
		[]string{"top_frame"},
	)
	goroutineUptime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "goroutine_uptime",
			Help:      "Uptime of goroutines in seconds",
			Buckets:   []float64{0.1, 0.25, 0.5, 1, 3, 5, 10, 30, 60, 120, 180},
		},
		[]string{"top_frame"},
	)
)

type goroutine struct {
	Id         int64
	ObservedAt time.Time
	Stack      []*proc.Function
	Exit       bool
}

// topFunctionName returns the name of the top function in the stack.
func (g *goroutine) topFrame() string {
	if len(g.Stack) == 0 {
		slog.Debug("goroutine stack is empty", slog.Int64("goroutine_id", g.Id), slog.Bool("exit", g.Exit))
		return ""
	}
	f := g.Stack[len(g.Stack)-1]
	if f == nil {
		return ""
	}
	if len(g.Stack) > 2 && f.Name == "runtime.gcWriteBarrier" {
		// runtime.gcWriteBarrier is used to track modifications to pointer values in heap-allocated objects.
		// This tracking is essential for the garbage collector to correctly identify which objects are still
		// reachable and, therefore, should not be collected.
		// Implementation: https://github.com/golang/go/blob/go1.21.6/src/runtime/asm_amd64.s#L1676-L1694
		// Great blog: https://ihagopian.com/posts/write-barriers-in-the-go-garbage-collector
		return g.Stack[len(g.Stack)-2].Name
	}
	return f.Name
}

type reporter struct {
	goroutineQueue <-chan goroutine
	goroutineMap   sync.Map
}

var reportInterval = 500 * time.Millisecond

func (r *reporter) run(ctx context.Context) {
	go r.reportUptime(ctx)
	go r.subscribe(ctx)
	<-ctx.Done()
}

func (r *reporter) reportUptime(ctx context.Context) {
	ticker := time.NewTicker(reportInterval)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			ctx, task := trace.NewTask(ctx, "reporter.report_goroutine_uptime")
			trace.WithRegion(ctx, "reporter.report_goroutine_uptime.iterate_goroutine_map", func() {
				r.goroutineMap.Range(func(_, value any) bool {
					g := value.(goroutine)
					goroutineUptime.WithLabelValues(g.topFrame()).Observe(time.Since(g.ObservedAt).Seconds())
					return true
				})
			})
			task.End()
		}
	}
}

func (r *reporter) subscribe(ctx context.Context) {
	for g := range r.goroutineQueue {
		ctx, task := trace.NewTask(ctx, "reporter.store_goroutine")
		r.storeGoroutine(ctx, g)
		task.End()
	}
}

func (r *reporter) storeGoroutine(ctx context.Context, g goroutine) {
	v, loaded := r.goroutineMap.Load(g.Id)
	if loaded {
		_, task := trace.NewTask(ctx, "reporter.store_goroutine_exit")
		oldg := v.(goroutine)
		uptime := time.Since(oldg.ObservedAt)
		logAttrs := []any{
			slog.Duration("uptime", uptime),
			slog.Int64("goroutine_id", g.Id),
			// Don't use g.Stack since goexit1 doesn't have informative stack.
			stackLogAttr(oldg.Stack),
		}
		slog.Info("goroutine is terminated", logAttrs...)
		goroutineExit.WithLabelValues(oldg.topFrame()).Inc()
		goroutineUptime.WithLabelValues(oldg.topFrame()).Observe(uptime.Seconds())
		r.goroutineMap.Delete(oldg.Id)
		task.End()
		return
	}
	if g.Exit {
		// Avoid storing goroutines that lack a corresponding newproc1 pair.
		return
	}
	_, task := trace.NewTask(ctx, "reporter.store_goroutine_creation")
	goroutineCreation.WithLabelValues(g.topFrame()).Inc()
	r.goroutineMap.Store(g.Id, g)
	task.End()
}

// LogAttr returns a slog.Attr that can be used to log the stack.
func stackLogAttr(stack []*proc.Function) slog.Attr {
	attrs := make([]any, len(stack))
	for i, f := range stack {
		if f == nil {
			panic("stack must not have nil function")
		}
		attrs[i] = slog.String(fmt.Sprintf("%d", i), f.Name)
	}
	return slog.Group("stack", attrs...)
}
