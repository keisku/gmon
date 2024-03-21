package main_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/require"
)

func Test_e2e(t *testing.T) {
	fixture, err := runProcess(os.Stdout, os.Stderr, "/usr/bin/fixture")
	if err != nil {
		t.Fatalf("failed to run fixture: %v", err)
	}

	// Wait for fixture to be ready.
	time.Sleep(time.Second)

	var gmonLogs bytes.Buffer
	gmon, err := runProcess(
		&gmonLogs, &gmonLogs,
		"/usr/bin/gmon",
		"-path",
		"/usr/bin/fixture",
		"-metrics",
		"5500",
		"-level",
		"DEBUG",
	)
	if err != nil {
		t.Fatalf("failed to run gmon: %v", err)
	}
	// Wait for gmon to be ready.
	time.Sleep(time.Second)

	t.Cleanup(func() {
		procs := []*os.Process{fixture, gmon}
		for i := range procs {
			if procs[i] != nil {
				if err := procs[i].Kill(); err != nil {
					t.Logf("failed to kill process: %v", err)
				}
			}
		}
	})

	requestFixtureCount := 3
	for range requestFixtureCount {
		resp, err := http.Get("http://localhost:8080/get/200")
		require.NoError(t, err, "GET /get/200 of fixture server failed")
		require.Equal(t, http.StatusOK, resp.StatusCode, "expect 200 from GET /get/200 of fixture server")
	}

	// Wait gmon detects goroutine events and writes logs.
	time.Sleep(time.Second)

	evaluateGmonOutput(t, &gmonLogs, requestFixtureCount)
	evaluateGmonMetrics(t)
}

func runProcess(stdout, stderr io.Writer, name string, arg ...string) (*os.Process, error) {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to run %q: %w", cmd, err)
	}
	return cmd.Process, nil
}

func evaluateGmonOutput(t *testing.T, gmonLogs io.Reader, expectValidLineCount int) {
	// A valid line should have:
	// - msg="goroutine is created"
	// - goroutine_id=%d, where %d is an integer
	// - stack.%d=funcName, where %d is an integer and funcName is a function name
	//   - When a HTTP server receives a request, it should cause a goroutine and have a stack trace.
	validLineCount := 0

	scanner := bufio.NewScanner(gmonLogs)
	for scanner.Scan() {
		// Valid line example:
		// time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=22 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*connReader).startBackgroundRead stack.4=net/http.(*conn).serve stack.5=net/http.(*Server).Serve.gowrap3 stack.6=runtime.goexit
		text := scanner.Text()

		if !strings.Contains(text, "msg=\"goroutine is created\"") {
			continue
		}

		goroutineIdBegin := strings.Index(text, "goroutine_id=")
		require.Greaterf(t, goroutineIdBegin, 8, "goroutine_id is not found in %q", text)
		goroutineIdEnd := strings.Index(text[goroutineIdBegin:], " ")
		goroutineId, err := strconv.Atoi(strings.Split(text[goroutineIdBegin:goroutineIdBegin+goroutineIdEnd], "=")[1])
		require.NoErrorf(t, err, "goroutine_id is not an integer in %q", text)
		require.Greaterf(t, goroutineId, 0, "goroutine_id is not a positive integer in %q", text)

		hasValidStack := false
		for stackIdx := 0; ; stackIdx++ {
			stackBegin := strings.Index(text, fmt.Sprintf("stack.%d=", stackIdx))
			if stackBegin < 0 {
				break
			}
			stackEnd := strings.Index(text[stackBegin:], " ")
			if stackEnd < 0 {
				break
			}
			stackValue := strings.Split(text[stackBegin:stackBegin+stackEnd], "=")[1]
			require.NotEmptyf(t, stackValue, "stack.%d should have a function name in %q", stackIdx, text)
			hasValidStack = true
		}
		require.Truef(t, hasValidStack, "no stack trace is found in %q", text)
		validLineCount++
	}

	require.Greaterf(t, validLineCount, expectValidLineCount, "valid line count is less than %d", expectValidLineCount)
}

func evaluateGmonMetrics(t *testing.T) {
	resp, err := http.Get("http://localhost:5500/metrics")
	require.NoError(t, err, "GET /metrics of gmon")
	require.Equal(t, http.StatusOK, resp.StatusCode, "expect 200 from GET /metrics of gmon")
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read response body from GET /metrics of gmon")
	defer func() {
		if t.Failed() {
			t.Logf("------ response body ------\n%s\n------ response body ------", b)
		}
	}()

	expectedMetrics := []string{
		"gmon_goroutine_creation",
		"gmon_goroutine_exit",
		"gmon_goroutine_uptime",
	}
	// Due to the high cardinality concern, we add up to 5 stack labels to metrics.
	expectedLabels := map[string]struct{}{
		"stack_0": {},
		"stack_1": {},
		"stack_2": {},
		"stack_3": {},
		"stack_4": {},
	}
	actualMetrics := make(map[string][]*dto.Metric)

	dec := expfmt.NewDecoder(bytes.NewReader(b), expfmt.NewFormat(expfmt.TypeTextPlain))
	for {
		var mf dto.MetricFamily
		err := dec.Decode(&mf)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "decode response body of GET /metrics")
		actualMetrics[mf.GetName()] = mf.GetMetric()
	}
	for _, expected := range expectedMetrics {
		ms, ok := actualMetrics[expected]
		require.Truef(t, ok, "metric %q is not found", expected)
		for _, m := range ms {
			for _, l := range m.GetLabel() {
				_, ok := expectedLabels[l.GetName()]
				require.Truef(t, ok, "%q doesn't exist in %q", l.GetName(), m)
				require.NotEmptyf(t, l.GetValue(), "%q should not have an empty", l.GetName())
				require.NotEqualf(t, "none", l.GetValue(), "%q should not have \"none\"", l.GetName())
			}
		}
	}
}
