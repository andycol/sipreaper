# internal/banner — XDP source-IP drop enforcer

This package implements the optional `enforcer.xdp` backend: an eBPF/XDP program
that drops banned source IPs at the NIC/driver layer, before netfilter and
before the AF_PACKET tap.

## Layout

| File | Build | Purpose |
|------|-------|---------|
| `bpf/xdp_ban.c` | (clang) | The XDP program. PASS/DROP only, fail-open, raw-byte v4 key. |
| `gen.go` | `ignore` | Hosts the `//go:generate bpf2go` directive. |
| `keys.go` / `keys_test.go` | all | Cross-platform `net.IP`→map-key byte-layout contract + tests. |
| `enforcer_linux.go` | `linux && xdp` | The `action.Enforcer` impl: load/attach/pin/reconcile/ban/unban. |
| `preflight_linux.go` | `linux && xdp` | Kernel/BTF/bpffs/iface host checks. |
| `enforcer_stub.go` | `!linux || !xdp` | Inert stub so default builds do not need generated eBPF bindings. |
| `progtest_test.go` | `linux && xdp` | Root-gated `BPF_PROG_TEST_RUN` classification + round-trip tests. |
| `bpf_bpfel.{go,o}` / `bpf_bpfeb.{go,o}` | `linux && xdp` (generated) | Local build artifacts from `make generate`. |

## Generated artifacts

`enforcer_linux.go` and the progtest reference symbols (`bpfObjects`,
`loadBpfObjects`, `bpfIn6Key`, …) produced by **bpf2go** are compiled only for
`-tags xdp` builds. Generate them on a Linux host with clang/LLVM >= 11,
libbpf-dev and `linux-headers-$(uname -r)`:

```bash
make generate   # emits bpf_bpfel.{go,o} and bpf_bpfeb.{go,o}
make build-xdp
```

The generated files are tagged `//go:build linux && xdp`, so plain Linux and
darwin checkouts compile the stub and never need them.

Plain `make build` needs only gcc + libpcap-dev — not the eBPF toolchain.
