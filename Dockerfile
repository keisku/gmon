FROM golang:1.22
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
	tar -xzf /tmp/bpftool.tar.gz -C /usr/bin/ && \
	chmod +x /usr/bin/bpftool && \
	go install honnef.co/go/tools/cmd/staticcheck@latest
WORKDIR /src
CMD ["make"]
