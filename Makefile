.PHONY: all format test build

all: format build

format:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker run --rm -v $(shell pwd):/src \
		-e GOFLAGS="-buildvcs=false" \
		gmonbuildenv \
		bash \
		-c "go mod tidy && go vet ./... && staticcheck ./... && find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;"

build:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker run --rm -v $(shell pwd):/src \
		-e GOFLAGS="-buildvcs=false" \
		-e BPF_CLANG="clang" \
		-e BPF_CFLAGS="-O2 -g -Wall -Werror" \
		gmonbuildenv \
		bash \
		-c "bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h && go generate -x ./... && CGO_ENABLED=0 go build -o /src/bin/gmon"

test:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker build -t gmone2e -f Dockerfile.e2e .
	docker run --rm --privileged \
		-v ./bin/gmon:/usr/bin/gmon \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		gmone2e
