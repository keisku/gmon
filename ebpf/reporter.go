package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/go-delve/delve/pkg/proc"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type goroutine struct {
	Id         int64
	ObservedAt time.Time
	Stack      []*proc.Function
	Exit       bool
}

// topFunctionName returns the name of the top function in the stack.
func (g *goroutine) topFrame() string {
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
	goroutineQueue         <-chan goroutine
	goroutineMap           sync.Map
	monitorExpiryThreshold time.Duration
	metircsQueue           chan<- pmetric.Metrics
	lastInt64Sum           sync.Map
}

var reportInterval = 500 * time.Millisecond

func (r *reporter) run(ctx context.Context) {
	go func() {
		for range time.Tick(reportInterval) {
			if err := ctx.Err(); err != nil {
				return
			}
			ms := pmetric.NewMetrics()
			sms := ms.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
			m := sms.Metrics().AppendEmpty()
			m.SetName("goroutine_uptime")
			m.SetDescription("Milliseconds since the goroutine was created")
			m.SetUnit("milliseconds")
			dps := m.SetEmptyGauge().DataPoints()
			r.goroutineMap.Range(func(_, value any) bool {
				g := value.(goroutine)
				uptime := time.Since(g.ObservedAt)
				logAttrs := []any{
					slog.Duration("uptime", uptime),
					slog.Int64("goroutine_id", g.Id),
					stackLogAttr(g.Stack),
				}
				slog.Info("goroutine uptime", logAttrs...)
				dp := dps.AppendEmpty()
				dp.SetDoubleValue(float64(uptime.Milliseconds()))
				dp.SetStartTimestamp(pcommon.NewTimestampFromTime(g.ObservedAt))
				dp.Attributes().PutStr("top_frame", g.topFrame())
				dp.Attributes().PutInt("goroutine_id", g.Id)
				if r.monitorExpiryThreshold > 0 && uptime > r.monitorExpiryThreshold {
					slog.Info(fmt.Sprintf("goroutine is still running after %s, then remove it from the monitoring targets", r.monitorExpiryThreshold), logAttrs...)
					r.goroutineMap.Delete(g.Id)
				}
				return true
			})
			r.metircsQueue <- ms
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

func (r *reporter) storeGoroutine(g goroutine) {
	ms := pmetric.NewMetrics()
	defer func() {
		r.metircsQueue <- ms
	}()
	sms := ms.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	v, loaded := r.goroutineMap.Load(g.Id)
	if loaded {
		oldg := v.(goroutine)
		uptime := time.Since(oldg.ObservedAt)
		logAttrs := []any{
			slog.Duration("uptime", uptime),
			slog.Int64("goroutine_id", g.Id),
			// Don't use g.Stack since goexit1 doesn't have informative stack.
			stackLogAttr(oldg.Stack),
		}
		slog.Info("goroutine is terminated", logAttrs...)
		termination := sms.Metrics().AppendEmpty()
		termination.SetName("goroutine_termination")
		termination.SetDescription("The number of goroutines that have been terminated")
		terminationSum := termination.SetEmptySum()
		terminationSum.SetIsMonotonic(true)
		terminationSum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
		terminationSumDp := terminationSum.DataPoints().AppendEmpty()
		terminationSumDp.SetIntValue(r.loadLastInt64Sum(fmt.Sprintf("termination_%s", oldg.topFrame())))
		terminationSumDp.Attributes().PutStr("top_frame", oldg.topFrame())
		r.goroutineMap.Delete(oldg.Id)
		return
	}
	if g.Exit {
		// Avoid storing goroutines that lack a corresponding newproc1 pair.
		return
	}
	creation := sms.Metrics().AppendEmpty()
	creation.SetName("goroutine_creation")
	creation.SetDescription("The number of goroutines that have been created")
	creationSum := creation.SetEmptySum()
	creationSum.SetIsMonotonic(true)
	creationSum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	creationSumDp := creationSum.DataPoints().AppendEmpty()
	creationSumDp.SetIntValue(r.loadLastInt64Sum(fmt.Sprintf("creation_%s", g.topFrame())))
	creationSumDp.Attributes().PutStr("top_frame", g.topFrame())
	r.goroutineMap.Store(g.Id, g)
}

func (r *reporter) loadLastInt64Sum(key string) int64 {
	v, ok := r.lastInt64Sum.LoadOrStore(key, int64(1))
	if ok {
		return v.(int64)
	}
	return 1
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
