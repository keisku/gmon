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
```

Example

```bash
sudo gmon -path /path/to/executable
time=2024-01-08T11:54:58.587Z level=INFO msg=runtime.newproc1 goroutine_id=1937 stack_id=79 stack.0="runtime.newproc at /snap/go/10455/src/runtime/proc.go:4477" stack.1="runtime.systemstack at /snap/go/10455/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10455/src/runtime/proc.go:4480" stack.3="main.main at /home/ubuntu/workspace/gmon/bin/fixture/main.go:16" stack.4="runtime.main at /snap/go/10455/src/runtime/internal/atomic/types.go:194" stack.5="runtime.goexit at /snap/go/10455/src/runtime/asm_amd64.s:1651"
time=2024-01-08T11:54:58.587Z level=INFO msg=runtime.goexit1 goroutine_id=1937 stack_id=614 stack.0="runtime.goexit1 at /snap/go/10455/src/runtime/proc.go:3850"
time=2024-01-08T11:54:58.787Z level=INFO msg=runtime.newproc1 goroutine_id=1864 stack_id=79 stack.0="runtime.newproc at /snap/go/10455/src/runtime/proc.go:4477" stack.1="runtime.systemstack at /snap/go/10455/src/runtime/asm_amd64.s:513" stack.2="runtime.newproc at /snap/go/10455/src/runtime/proc.go:4480" stack.3="main.main at /home/ubuntu/workspace/gmon/bin/fixture/main.go:16" stack.4="runtime.main at /snap/go/10455/src/runtime/internal/atomic/types.go:194" stack.5="runtime.goexit at /snap/go/10455/src/runtime/asm_amd64.s:1651"
time=2024-01-08T11:54:58.787Z level=INFO msg=runtime.goexit1 goroutine_id=1864 stack_id=614 stack.0="runtime.goexit1 at /snap/go/10455/src/runtime/proc.go:3850"
time=2024-01-08T11:54:58.988Z level=INFO msg=runtime.goexit1 goroutine_id=1865 stack_id=614 stack.0="runtime.goexit1 at /snap/go/10455/src/runtime/proc.go:3850"
...
```

# Build

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
make
```
