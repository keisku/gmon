#!/bin/bash

set -xue

go mod tidy
go vet ./...
staticcheck ./...
find . -type f \( -name '*.[ch]' -and -not -name 'vmlinux.h' \) -exec clang-format -i {} \;
