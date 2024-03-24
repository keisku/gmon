.PHONY: all format test build

all: format build

format:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker run --rm -v $(shell pwd):/src \
		-e GOFLAGS="-buildvcs=false" \
		gmonbuildenv \
		script/format.sh

build:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker run --rm -v $(shell pwd):/src \
		-e GOFLAGS="-buildvcs=false" \
		-e BPF_CLANG="clang" \
		-e BPF_CFLAGS="-O2 -g -Wall -Werror" \
		gmonbuildenv \
		script/build.sh

test:
	docker build -t gmonbuildenv -f Dockerfile.buildenv .
	docker build -t gmone2e -f Dockerfile.e2e .
	docker run --rm --privileged \
		-v ./bin/gmon:/usr/bin/gmon \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		gmone2e
