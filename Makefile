BINARY := sipreaper
PKG := github.com/andycol/sipreaper
VERSION := 0.1.0

.PHONY: build build-xdp test clean generate

# generate (re)compiles the XDP object and its Go bindings via bpf2go. It needs
# the eBPF toolchain — clang/LLVM >= 11, libbpf-dev and linux-headers — and only
# runs on Linux. Plain `make build` does not include XDP and does not need the
# generated bindings.
generate:
	go generate ./...

build:
	go build -o $(BINARY) ./cmd/sipreaper

build-xdp:
	go build -tags xdp -o $(BINARY) ./cmd/sipreaper

test:
	go test ./... -v -race

clean:
	rm -f $(BINARY)
