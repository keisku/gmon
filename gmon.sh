#!/bin/bash

set -e -x

arch=$(uname -m)
if [ "$arch" != "x86_64" ]; then
  echo "Unsupported architecture: $arch"
  exit 1
fi

kernel_version=$(uname -r)
major_version=$(echo $kernel_version | cut -d. -f1)
minor_version=$(echo $kernel_version | cut -d. -f2)
if [ "$major_version" -gt 5 ] || ([ "$major_version" -eq 5 ] && [ "$minor_version" -ge 8 ]); then
    echo "Your kernel version is $kernel_version"
else
    echo "Your kernel version should be >= 5.8, got $kernel_version"
    exit 1
fi

if [ "$1" = "build" ] || [ "$1" = "install" ] || [ "$1" = "test" ] || [ "$1" = "format" ]; then
  echo "Running $1 on $arch"
else
  echo "Unsupported command: $1"
  exit 1
fi

image_buildenv=gmon-buildenv-$arch
dockerfile_buildenv=$(mktemp)
cat > "$dockerfile_buildenv" <<EOF
FROM debian:bookworm-20240513@sha256:fac2c0fd33e88dfd3bc88a872cfb78dcb167e74af6162d31724df69e482f886c
RUN <<END
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  clang-14 \
  clang-format-14 \
  git \
  libbpf-dev \
  llvm-14 \
  wget
ln -s /usr/bin/llvm-strip-14 /usr/bin/llvm-strip
ln -s /usr/bin/clang-14 /usr/bin/clang
ln -s /usr/bin/clang-format-14 /usr/bin/clang-format
wget -O- --no-check-certificate https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool-v7.3.0-amd64.tar.gz | tar -xzf - -C /usr/bin && chmod +x /usr/bin/bpftool
wget -O- --no-check-certificate https://go.dev/dl/go1.23.1.linux-amd64.tar.gz | tar -xzf - -C /usr/local && chmod +x /usr/local/go/bin/go && ln -s /usr/local/go/bin/go /usr/bin/go
END
WORKDIR /usr/src
COPY go.mod go.mod
RUN go mod download
EOF
docker build --platform linux/$arch -t $image_buildenv -f "$dockerfile_buildenv" .
rm "$dockerfile_buildenv"

rm -f $(pwd)/bin/gmon || true
docker run --platform linux/$arch -i \
-v $(pwd):/usr/src \
-e BPF_CLANG="clang" \
-e BPF_CFLAGS="-O2 -g -Wall -Werror" \
--rm $image_buildenv bash -c '\
  git config --global --add safe.directory /usr/src && \
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/c/vmlinux.h && \
  go generate -x ./... && \
  GOFLAGS="-buildvcs=auto" CGO_ENABLED=0 go build \
  -ldflags "-s -w -X main.Version=0.0.0-dev" \
  -o /usr/src/bin/gmon'
if [ "$1" = "build" ]; then
  exit 0
fi

if [ "$1" = "install" ]; then
  sudo rm -f /usr/bin/gmon || true
  sudo install ./bin/gmon /usr/bin/
  exit 0
fi

if [ "$1" = "format" ]; then
  docker run --platform linux/$arch -i \
  -v $(pwd):/usr/src \
  --rm $image_buildenv bash -c '\
  go mod tidy && \
  go vet ./... && \
  find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;'
  exit 0
fi

if [ "$1" = "test" ]; then
  image_e2e=gmon-e2e-$arch
  dockerfile_e2e=$(mktemp)
  cat > "$dockerfile_e2e" <<EOF
FROM $image_buildenv
WORKDIR /src/fixture
COPY ./fixture .
RUN go mod tidy && go build && install fixture /usr/bin/
WORKDIR /src
COPY . .
CMD ["go", "test", "-v", "./..."]
EOF
  docker build --platform linux/$arch -t $image_e2e -f "$dockerfile_e2e" .
  rm "$dockerfile_e2e"
  docker run --rm --privileged --platform linux/$arch -i -v /sys/kernel/debug:/sys/kernel/debug:ro -v ./bin/gmon:/usr/bin/gmon $image_e2e
  exit 0
fi
