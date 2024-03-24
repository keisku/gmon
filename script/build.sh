#!/bin/bash

set -xue

bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h
go generate -x ./...
CGO_ENABLED=0 go build -o /src/bin/gmon
