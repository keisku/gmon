package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

var (
	fixturePath  = flag.String("fixture", "/src/e2e/fixture/fixture", "Path to fixture program")
	gmonPath     = flag.String("gmon", "/src/bin/gmon", "Path to gmon")
	requestCount = flag.Int("request", 3, "Number of HTTP requests to be made to fixture server")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	if err := runTest(ctx); err != nil {
		slog.Error("e2e test failed", slog.Any("error", err))
		os.Exit(1)
	}
	slog.Info("e2e test passed!")
}

func runTest(ctx context.Context) error {
	slog.Info("Run fixture server to be a target of gmon monitoring")
	fixture, err := runFixture(ctx)
	if err != nil {
		return err
	}
	defer fixture.Kill()

	slog.Info("Run gmon to monitor fixture goroutines")
	gmon, err := runGmon(ctx)
	if err != nil {
		return err
	}
	defer gmon.Kill()

	// Wait gmon becomes ready to monitor fixture.
	time.Sleep(time.Second)

	slog.Info("Make GET requests to fixture server to cause goroutines")
	for range *requestCount {
		resp, err := http.Get("http://localhost:8080/get/200")
		if err != nil {
			return fmt.Errorf("GET /get/200: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expect 200 from GET /get/200: %s", resp.Status)
		}
	}

	// Wait gmon detects goroutine events and writes logs.
	time.Sleep(time.Second)

	slog.Info("Validate gmon output regarding goroutines of fixture")
	if err := testGmonOutput(ctx); err != nil {
		return err
	}

	slog.Info("Validate GET /metrics output of gmon regarding fixture goroutines")
	if err := testGmonMetrics(ctx); err != nil {
		return err
	}
	return nil
}

func runFixture(ctx context.Context) (*os.Process, error) {
	fixture := exec.CommandContext(ctx, *fixturePath)
	if err := fixture.Start(); err != nil {
		return nil, fmt.Errorf("start fixture: %w", err)
	}
	slog.Info("fixture runs", slog.String("cmdline", fixture.String()))
	return fixture.Process, nil
}

const gmonLogPath = "/tmp/testGmonOutput.log"

func runGmon(ctx context.Context) (*os.Process, error) {
	logFile, err := os.Create(gmonLogPath)
	if err != nil {
		return nil, fmt.Errorf("create %q: %w", gmonLogPath, err)
	}
	gmon := exec.CommandContext(
		ctx,
		*gmonPath,
		"-path",
		*fixturePath,
		"-metrics",
		"5500",
		"-level",
		"DEBUG",
	)
	gmon.Stdout = logFile
	gmon.Stderr = logFile
	if err := gmon.Start(); err != nil {
		return nil, fmt.Errorf("start gmon: %w", err)
	}
	slog.Info("gmon runs", slog.String("cmdline", gmon.String()))
	return gmon.Process, nil
}

func testGmonOutput(_ context.Context) (err error) {
	defer func() {
		if err != nil {
			slog.Error("testGmonOutput failed, print actual gmon logs")
			b, err := os.ReadFile(gmonLogPath)
			if err != nil {
				slog.Error("failed to read", slog.String("path", gmonLogPath), slog.Any("error", err))
				return
			}
			fmt.Printf("------  BEGIN  ------\n%s\n------  END  ------\n", b)
		}
	}()

	gmonLogFile, err := os.Open(gmonLogPath)
	if err != nil {
		return fmt.Errorf("read gmon logs: %w", err)
	}
	defer gmonLogFile.Close()

	// A valid line should have:
	// - msg="goroutine is created"
	// - goroutine_id=%d, where %d is an integer
	// - stack.%d=funcName, where %d is an integer and funcName is a function name
	//   - When a HTTP server receives a request, it should cause a goroutine and have a stack trace.
	validLineCount := 0

	scanner := bufio.NewScanner(gmonLogFile)
	for scanner.Scan() {
		// Valid line example:
		// time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=22 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*connReader).startBackgroundRead stack.4=net/http.(*conn).serve stack.5=net/http.(*Server).Serve.gowrap3 stack.6=runtime.goexit
		text := scanner.Text()

		if !strings.Contains(text, "msg=\"goroutine is created\"") {
			continue
		}

		goroutineIdBegin := strings.Index(text, "goroutine_id=")
		if goroutineIdBegin < 0 {
			return fmt.Errorf("goroutine_id is not found in %q", text)
		}
		goroutineIdEnd := strings.Index(text[goroutineIdBegin:], " ")
		_, err := strconv.Atoi(strings.Split(text[goroutineIdBegin:goroutineIdBegin+goroutineIdEnd], "=")[1])
		if err != nil {
			return fmt.Errorf("goroutine_id is not an int in %q: %w", text, err)
		}

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
			if stackValue == "" {
				return fmt.Errorf("stack.%d should have a function name in %q", stackIdx, text)
			}
			hasValidStack = true
		}
		if !hasValidStack {
			return fmt.Errorf("no stack trace is found in %q", text)
		}

		validLineCount++
	}
	if validLineCount < *requestCount {
		return fmt.Errorf("valid line count is less than %d: actual=%d", *requestCount, validLineCount)
	}
	return nil
}

func testGmonMetrics(_ context.Context) (err error) {
	resp, err := http.Get("http://localhost:5500/metrics")
	if err != nil {
		return fmt.Errorf("GET /metrics: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expect 200 from GET /metrics: %s", resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body from GET /metrics: %w", err)
	}
	defer func() {
		if err != nil {
			slog.Error("testGmonMetrics failed, print actual gmon metrics")
			fmt.Printf("------  BEGIN  ------\n%s\n------  END  ------\n", b)
		}
	}()

	// TODO: Should test contents of metric value and labels.
	expectedMetrics := []string{
		"gmon_goroutine_creation",
		"gmon_goroutine_exit",
		"gmon_goroutine_uptime",
	}
	actualMetrics := make(map[string]struct{})

	dec := expfmt.NewDecoder(bytes.NewReader(b), expfmt.NewFormat(expfmt.TypeTextPlain))
	for {
		var mf dto.MetricFamily
		if err := dec.Decode(&mf); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("decode /metrics: %w", err)
		}
		actualMetrics[mf.GetName()] = struct{}{}
	}
	for _, expected := range expectedMetrics {
		if _, ok := actualMetrics[expected]; !ok {
			return fmt.Errorf("%s is missing", expected)
		}
	}
	return nil
}
