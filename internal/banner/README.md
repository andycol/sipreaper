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
| `enforcer_linux.go` | `linux` | The `action.Enforcer` impl: load/attach/pin/reconcile/ban/unban. |
| `preflight_linux.go` | `linux` | Kernel/BTF/bpffs/iface host checks. |
| `enforcer_stub.go` | `!linux` | Inert stub so the module builds/runs on darwin etc. |
| `progtest_test.go` | `linux` | Root-gated `BPF_PROG_TEST_RUN` classification + round-trip tests. |
| `bpf_bpfel.{go,o}` / `bpf_bpfeb.{go,o}` | `linux` (generated) | **Committed build artifacts** from `make generate`. |

## Generated artifacts

`enforcer_linux.go` and the progtest reference symbols (`bpfObjects`,
`loadBpfObjects`, `bpfIn6Key`, …) produced by **bpf2go**. They are NOT in source
control until you run, on a Linux host with clang/LLVM ≥ 11, libbpf-dev and
`linux-headers-$(uname -r)`:

```bash
make generate   # emits bpf_bpfel.{go,o} and bpf_bpfeb.{go,o}; commit them
```

The generated files are tagged `//go:build linux`, so a darwin checkout compiles
the stub and never needs them. CI regenerates them on every run (see
`.github/workflows/ci.yml`) and verifies the generated Go is reproducible.

Once committed, plain `make build` needs only gcc + libpcap-dev — not the eBPF
toolchain.
