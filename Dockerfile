FROM golang:1.22
RUN if [ "$(uname -m)" != "x86_64" ]; then \
        echo "Unsupported CPU architecture! gmon supports only x86_64." >&2; \
        exit 1; \
    fi
RUN if [ "$(uname -r | cut -d'-' -f1)" \< "6.2.0" ]; then \
        echo "Unsupported kernel version! gmon supports kernel versions at least 6.2.0." >&2; \
        exit 1; \
    fi
RUN apt-get update && apt-get install -y \
	bcc \
	curl \
	llvm \
	clang \
	libbpf-dev \
	clang-format \
	build-essential \
	linux-headers-generic && \
	curl -L -o /tmp/bpftool.tar.gz https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool-v7.3.0-amd64.tar.gz && \
	tar -xzf /tmp/bpftool.tar.gz -C /usr/bin/ && rm /tmp/bpftool.tar.gz && \
	chmod +x /usr/bin/bpftool && \
	go install honnef.co/go/tools/cmd/staticcheck@latest
COPY ./e2e /src/e2e
WORKDIR /src/e2e/fixture
RUN go build
WORKDIR /src/e2e
RUN go build
WORKDIR /src
COPY ./go.mod ./go.mod
RUN go mod download
CMD ["make", "build"]
