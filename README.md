# Goroutine MONitor (gmon)

`gmon is a tool designed to monitor the creation and destruction of goroutines in a Go program, drawing inspiration from the presentation [Real World Debugging with eBPF](https://www.usenix.org/conference/srecon23apac/presentation/liang).

# Pre-requisites

- Kernel version >= 6.2.0
- amd64 (x86_64) architecture

# Build

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
```
