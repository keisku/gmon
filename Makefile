CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

.PHONY: all format generate build

all: generate format build

build: export GOFLAGS := -buildvcs=false
build:
	CGO_ENABLED=0 go build -o ./bin/gmon

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h
	go generate -x ./...

format: export GOFLAGS := -buildvcs=false
format:
	go mod tidy
	staticcheck ./...
	find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;

test:
	go vet ./...
	go test -race -v ./...
