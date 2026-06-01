BINARY := sipreaper
PKG := github.com/andycol/sipreaper
VERSION := 0.1.0

.PHONY: build test clean generate

# generate (re)compiles the XDP object and its Go bindings via bpf2go. It needs
# the eBPF toolchain — clang/LLVM >= 11, libbpf-dev and linux-headers — and only
# runs on Linux. The committed bpf_bpfel.{go,o} / bpf_bpfeb.{go,o} mean plain
# `make build` does NOT need this toolchain (gcc + libpcap-dev suffice).
generate:
	go generate ./...

build:
	go build -o $(BINARY) ./cmd/sipreaper

test:
	go test ./... -v -race

clean:
	rm -f $(BINARY)
