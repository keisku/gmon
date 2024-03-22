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
	namespace      = "gmon"
	stackLabelKeys = []string{"stack_0", "stack_1", "stack_2", "stack_3", "stack_4"} // 0 is the top
	goroutineExit  = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "goroutine_exit",
			Help:      "The number of goroutines that have been exited",
		},
		stackLabelKeys,
	)
	goroutineCreation = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "goroutine_creation",
			Help:      "The number of goroutines that have been creaated",
		},
		stackLabelKeys,
	)
	goroutineUptime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "goroutine_uptime",
			Help:      "Uptime of goroutines in seconds",
			Buckets:   []float64{1, 3, 5, 10, 30, 60, 120, 180},
		},
		stackLabelKeys,
	)
)

type goroutine struct {
	Id         int64
	ObservedAt time.Time
	Stack      []*proc.Function
	Exit       bool
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
					goroutineUptime.With(stackLabels(g.Stack)).Observe(time.Since(g.ObservedAt).Seconds())
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
		oldg, ok := v.(goroutine)
		if !ok {
			slog.Error("goroutineMap has unexpected value", slog.Any("value", v))
			return
		}
		goroutineExit.With(stackLabels(oldg.Stack)).Inc()
		goroutineUptime.With(stackLabels(oldg.Stack)).Observe(time.Since(oldg.ObservedAt).Seconds())
		r.goroutineMap.Delete(oldg.Id)
		task.End()
		return
	}
	if g.Exit {
		// Avoid storing goroutines that lack a corresponding newproc1 pair.
		return
	}
	_, task := trace.NewTask(ctx, "reporter.store_goroutine_creation")
	slog.Info("goroutine is created", slog.Int64("goroutine_id", g.Id), stackLogAttr(g.Stack))
	goroutineCreation.With(stackLabels(g.Stack)).Inc()
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

// stackLabels generates a set of Prometheus labels for the top functions in the stack.
// If the stack has fewer than expected functions, it fills the remaining labels with "none".
func stackLabels(stack []*proc.Function) prometheus.Labels {
	labels := prometheus.Labels{}

	// Ensure to only process the top 5 elements, or the stack length if shorter.
	topN := len(stack)
	if topN > len(stackLabelKeys) {
		topN = len(stackLabelKeys)
	}

	for i := 0; i < len(stackLabelKeys); i++ {
		labelKey := fmt.Sprintf("stack_%d", i)
		if i < topN {
			// Stack is reversed, so we start from the end of the slice.
			labels[labelKey] = stack[len(stack)-1-i].Name
		} else {
			labels[labelKey] = "none"
		}
	}

	return labels
}
