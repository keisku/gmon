# Goroutine MONitor (gmon)

`gmon` is a tool designed to monitor the creation and destruction of goroutines in a Go program, drawing inspiration from the presentation [Real World Debugging with eBPF](https://www.usenix.org/conference/srecon23apac/presentation/liang).

# Pre-requisites

- Kernel version >= 6.2.0
- amd64 (x86_64) architecture

# Usage

```
Usage of gmon:
  -level value
    	log level could be one of ["DEBUG" "INFO" "WARN" "ERROR"] (default INFO)
  -monitor-expiry-threshold string
    	Remove a goroutine from monitoring when its uptime exceeds this value. If set to 0, the goroutine will never be deleted. E.g., "0", "100ms", "1s500ms". See https://pkg.go.dev/time#ParseDuration (default "0")
  -path string
    	Path to executable file to be monitored (required)
  -pid int
    	Useful when tracing programs that have many running instances
  -pprof-port int
    	Port to be used for pprof server
  -uptime-threshold string
    	Uptime threshold for logging. E.g., "0", "100ms", "1s500ms". See https://pkg.go.dev/time#ParseDuration (default "0")
```

Example

```bash
sudo gmon -path /path/to/executable -uptime-threshold 3s
time=2024-01-14T07:25:59.657Z level=INFO msg="goroutine is terminated" uptime=13.039920678s goroutine_id=633 stack.0="runtime.malg.func1 at /snap/go/10489/src/runtime/proc.go:4462" stack.1="runtime.systemstack at /snap/go/10489/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10489/src/runtime/proc.go:4480" stack.3="main.MyFunction2 at /path/to/executable/main.go:51" stack.4="main.main at /path/to/executable/main.go:32" stack.5="runtime.main at /snap/go/10489/src/runtime/proc.go:277" stack.6="runtime.goexit at /snap/go/10489/src/runtime/asm_amd64.s:1651"
time=2024-01-14T07:26:00.615Z level=INFO msg="goroutine is running" uptime=4.967739813s goroutine_id=726 stack.0="runtime.malg.func1 at /snap/go/10489/src/runtime/proc.go:4462" stack.1="runtime.systemstack at /snap/go/10489/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10489/src/runtime/proc.go:4480" stack.3="main.MyFunction3 at /path/to/executable/main.go:57" stack.4="main.main at /path/to/executable/main.go:36" stack.5="runtime.main at /snap/go/10489/src/runtime/proc.go:277" stack.6="runtime.goexit at /snap/go/10489/src/runtime/asm_amd64.s:1651"
```

# Build

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
make
```
