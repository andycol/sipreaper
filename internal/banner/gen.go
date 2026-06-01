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
// -tags linux pins the generated files to GOOS=linux so a darwin checkout
// (where the .o objects are absent and only enforcer_stub.go compiles) never
// tries to //go:embed a missing object.

package banner

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type in6_key bpf bpf/xdp_ban.c -- -O2 -g -Wall -Werror -I/usr/include
