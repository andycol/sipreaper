//go:build ignore

// This file exists only to host the go:generate directive for bpf2go; the
// `ignore` build tag keeps it out of every real build. Run `make generate`
// (or `go generate ./...`) on a Linux host with clang/LLVM >= 11, libbpf-dev
// and linux-headers installed. It compiles bpf/xdp_ban.c and emits the
// committed, linux-tagged Go bindings + objects:
//
//	bpf_bpfel.go / bpf_bpfel.o   (little-endian: 386, amd64, arm, arm64, ...)
//	bpf_bpfeb.go / bpf_bpfeb.o   (big-endian: s390x, mips, ...)
//
// -tags "linux,xdp" pins the generated files to explicit XDP builds so normal
// Linux installs do not need the eBPF toolchain or generated objects.

package banner

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux,xdp" -type in6_key bpf bpf/xdp_ban.c -- -O2 -g -Wall -Werror -I/usr/include
