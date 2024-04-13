# Goroutine MONitor (gmon)

`gmon` is a tool designed to monitor the creation and destruction of goroutines in a Go program, drawing inspiration from the presentation [Real World Debugging with eBPF](https://www.usenix.org/conference/srecon23apac/presentation/liang).

![gopher-sketch-science-welding](https://github.com/egonelbre/gophers/blob/63b1f5a9f334f9e23735c6e09ac003479ffe5df5/sketch/science/welding.png?raw=true)

# Prerequisites

- amd64 (x86_64)

# Usage

```
Usage of gmon:
  -level string
    	log level could be one of ["DEBUG" "INFO" "WARN" "ERROR"] (default "INFO")
  -metrics int
    	Port to be used for metrics server, /metrics endpoint (default 5500)
  -path string
    	Path to executable file to be monitored (required)
  -pid int
    	Useful when tracing programs that have many running instances
  -pprof int
    	Port to be used for pprof server. If 0, pprof server is not started
  -trace string
    	Path to Go runtime/trace output
```

## Stdout

`gmon` logs the creation of goroutines to stdout with stack traces.

```bash
sudo gmon -path /path/to/executable
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=22 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*connReader).startBackgroundRead stack.4=net/http.(*conn).serve stack.5=net/http.(*Server).Serve.gowrap3 stack.6=runtime.goexit
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=21 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*Server).Serve stack.4=net/http.(*Server).ListenAndServe stack.5=main.main.gowrap1 stack.6=runtime.goexit
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=23 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*Server).Serve stack.4=net/http.(*Server).ListenAndServe stack.5=main.main.gowrap1 stack.6=runtime.goexit
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=34 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*Server).Serve stack.4=net/http.(*Server).ListenAndServe stack.5=main.main.gowrap1 stack.6=runtime.goexit
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=24 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*connReader).startBackgroundRead stack.4=net/http.(*conn).serve stack.5=net/http.(*Server).Serve.gowrap3 stack.6=runtime.goexit
time=2024-03-20T05:10:57.752Z level=INFO msg="goroutine is created" goroutine_id=35 stack.0=runtime.newproc stack.1=runtime.systemstack stack.2=runtime.newproc stack.3=net/http.(*connReader).startBackgroundRead stack.4=net/http.(*conn).serve stack.5=net/http.(*Server).Serve.gowrap3 stack.6=runtime.goexit
```

## OpenMetrics

`gmon` exposes the following metrics in the [OpenMetrics](https://www.cncf.io/projects/openmetrics/) format on the `GET /metrics`.

- `gmon_goroutine_creation`
- `gmon_goroutine_exit`
- `gmon_goroutine_uptime`

```bash
curl -s http://localhost:5500/metrics

# HELP gmon_goroutine_creation The number of goroutines that have been creaated
# TYPE gmon_goroutine_creation counter
gmon_goroutine_creation{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc"} 1
gmon_goroutine_creation{stack_0="runtime.goexit",stack_1="net/http.(*Server).Serve.gowrap3",stack_2="net/http.(*conn).serve",stack_3="net/http.(*connReader).startBackgroundRead",stack_4="runtime.newproc"} 3
# HELP gmon_goroutine_exit The number of goroutines that have been exited
# TYPE gmon_goroutine_exit counter
gmon_goroutine_exit{stack_0="runtime.goexit",stack_1="net/http.(*Server).Serve.gowrap3",stack_2="net/http.(*conn).serve",stack_3="net/http.(*connReader).startBackgroundRead",stack_4="runtime.newproc"} 3
# HELP gmon_goroutine_uptime Uptime of goroutines in seconds
# TYPE gmon_goroutine_uptime histogram
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="1"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="3"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="5"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="10"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="30"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="60"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="120"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="180"} 2
gmon_goroutine_uptime_bucket{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc",le="+Inf"} 2
gmon_goroutine_uptime_sum{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc"} 0.9001332019999999
gmon_goroutine_uptime_count{stack_0="runtime.goexit",stack_1="main.main.gowrap1",stack_2="net/http.(*Server).ListenAndServe",stack_3="net/http.(*Server).Serve",stack_4="runtime.newproc"} 2
...skip...
```

# Development

Follow [the Docker installation guide](https://docs.docker.com/engine/install/#supported-platforms) to build and run tests.

```bash
# Build and output the binary to ./bin
./gmon.sh build
# Build and install the binary to /usr/bin
./gmon.sh install
# Run tests
./gmon.sh test
```
