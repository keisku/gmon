# Goroutine MONitor (gmon)

`gmon` is a tool designed to monitor the creation and destruction of goroutines in a Go program, drawing inspiration from the presentation [Real World Debugging with eBPF](https://www.usenix.org/conference/srecon23apac/presentation/liang).

# Pre-requisites

- Kernel version >= 6.2.0
- amd64 (x86_64) architecture

# Usage

```bash
Usage of gmon:
  -level value
    	log level could be one of ["DEBUG" "INFO" "WARN" "ERROR"] (default INFO)
  -path string
    	Path to executable file to be monitored (required)
  -pid int
    	Useful when tracing programs that have many running instances
  -pprof-port int
    	Port to be used for pprof server
  -uptime-debug string
    	Uptime threshold for debug level log. E.g., "0", "100ms", "1s500ms". We follow the same format as https://pkg.go.dev/time#ParseDuration (default "0")
  -uptime-error string
    	Uptime threshold for error level log. E.g., "0", "100ms", "1s500ms". We follow the same format as https://pkg.go.dev/time#ParseDuration (default "1m")
  -uptime-info string
    	Uptime threshold for info level log. E.g., "0", "100ms", "1s500ms". We follow the same format as https://pkg.go.dev/time#ParseDuration (default "1s")
  -uptime-warn string
    	Uptime threshold for warn level log. E.g., "0", "100ms", "1s500ms". We follow the same format as https://pkg.go.dev/time#ParseDuration (default "10s")
```

Example

```bash
sudo gmon -path /path/to/executable -uptime-info 3s -uptime-warn 20s
time=2024-01-14T07:25:59.657Z level=INFO msg="goroutine is terminated" uptime=13.039920678s goroutine_id=633 stack.0="runtime.malg.func1 at /snap/go/10489/src/runtime/proc.go:4462" stack.1="runtime.systemstack at /snap/go/10489/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10489/src/runtime/proc.go:4480" stack.3="main.MyFunction2 at /path/to/executable/main.go:51" stack.4="main.main at /path/to/executable/main.go:32" stack.5="runtime.main at /snap/go/10489/src/runtime/proc.go:277" stack.6="runtime.goexit at /snap/go/10489/src/runtime/asm_amd64.s:1651"
time=2024-01-14T07:26:00.615Z level=INFO msg="goroutine is running" uptime=4.967739813s goroutine_id=726 stack.0="runtime.malg.func1 at /snap/go/10489/src/runtime/proc.go:4462" stack.1="runtime.systemstack at /snap/go/10489/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10489/src/runtime/proc.go:4480" stack.3="main.MyFunction3 at /path/to/executable/main.go:57" stack.4="main.main at /path/to/executable/main.go:36" stack.5="runtime.main at /snap/go/10489/src/runtime/proc.go:277" stack.6="runtime.goexit at /snap/go/10489/src/runtime/asm_amd64.s:1651"
```

# Build

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
make
```
