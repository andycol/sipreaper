//go:build linux

// Package banner is sipreaper's XDP source-IP drop enforcer. It loads the
// compiled xdp_ban program, attaches it to the SIP-facing NIC (native driver
// mode where supported, generic/SKB mode otherwise), and drives two pinned
// kernel HASH maps (IPv4 / IPv6) that the program consults to decide
// XDP_DROP vs XDP_PASS.
//
// Safety posture (mirrors the existing enforcers' "log a warning, never be
// fatal" pattern): every failure path here is fail-open — the daemon keeps its
// iptables/ipset base enforcer if anything in Init() returns an error. The
// kernel program itself returns XDP_PASS for everything not explicitly banned.
//
// The generated bindings (bpfObjects, loadBpfObjects, bpfIn6Key) come from
// bpf_bpfel.go / bpf_bpfeb.go, produced by `make generate` (see gen.go).
package banner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andycol/sipreaper/internal/action"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// pinDir is where the maps live so bans survive a daemon restart. The link
// (the attachment) is deliberately NOT pinned: on SIGKILL the program detaches
// when the last fd closes (fail-open), while the pinned maps persist and are
// reconciled against the DB at the next startup.
const pinDir = "/sys/fs/bpf/sipreaper"

// schemaVersion stamps the pinned-map layout. Bump it whenever the map
// key/value shapes change; on a startup mismatch the daemon unlinks the stale
// pins and recreates them rather than failing into an unenforced state.
const schemaVersion uint32 = 1

// stats array indices — kept in lockstep with xdp_ban.c.
const (
	statPassed  uint32 = 0
	statDropped uint32 = 1
)

var _ action.Enforcer = (*XdpEnforcer)(nil)

// XdpEnforcer satisfies action.Enforcer and additionally exposes Close() plus
// diagnostics (Attached/Mode/MapEntries/Stats) that the daemon holds via a
// concrete handle (the interface intentionally stays minimal).
type XdpEnforcer struct {
	mu      sync.Mutex
	ifindex int
	iface   string
	auto    bool                // true => try driver then generic
	mode    link.XDPAttachFlags // used only when !auto

	objs     bpfObjects
	xdp      link.Link
	attached bool
	curMode  string
}

// NewXdpEnforcer validates the interface and the requested attach mode but does
// not touch the kernel yet (that is Init's job). mode is "" (auto), "native",
// or "generic".
func NewXdpEnforcer(iface, mode string) (*XdpEnforcer, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("xdp: interface %q: %w", iface, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("xdp: interface %q is down", iface)
	}
	auto, m, err := parseMode(mode)
	if err != nil {
		return nil, err
	}
	return &XdpEnforcer{ifindex: ifi.Index, iface: iface, auto: auto, mode: m}, nil
}

func parseMode(mode string) (auto bool, flag link.XDPAttachFlags, err error) {
	switch mode {
	case "", "auto":
		return true, 0, nil
	case "native", "driver":
		return false, link.XDPDriverMode, nil
	case "generic", "skb":
		return false, link.XDPGenericMode, nil
	default:
		return false, 0, fmt.Errorf("xdp: invalid mode %q (want \"\", \"native\" or \"generic\")", mode)
	}
}

func modeName(f link.XDPAttachFlags) string {
	switch f {
	case link.XDPDriverMode:
		return "driver"
	case link.XDPGenericMode:
		return "generic"
	default:
		return "auto"
	}
}

func (e *XdpEnforcer) Name() string { return "xdp" }

// Init removes the memlock limit, loads the program + (pinned) maps — handling a
// stale/incompatible pin by unlinking and recreating — then attaches with the
// configured mode/fallback. Any error here is returned to the daemon, which
// logs it and stays on the base enforcer (system-level fail-open).
func (e *XdpEnforcer) Init() error {
	if err := writeProbe(pinDir); err != nil {
		return fmt.Errorf("xdp: bpffs pin dir not writable (is /sys/fs/bpf mounted?): %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("xdp: remove memlock: %w", err)
	}
	if err := e.reconcileLoad(); err != nil {
		return err
	}
	if err := e.attachWithFallback(); err != nil {
		e.objs.Close()
		return err
	}
	return nil
}

// reconcileLoad loads the objects with the maps pinned under pinDir. A pinned
// map whose spec no longer matches (schema bump, old layout) is unlinked and
// recreated rather than failing closed.
func (e *XdpEnforcer) reconcileLoad() error {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return fmt.Errorf("xdp: mkdir pin dir: %w", err)
	}
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}

	err := loadBpfObjects(&e.objs, opts)
	if err != nil && isPinIncompatible(err) {
		if uerr := unlinkPins(pinDir); uerr != nil {
			return fmt.Errorf("xdp: unlink stale pins: %w", uerr)
		}
		err = loadBpfObjects(&e.objs, opts)
	}
	if err != nil {
		return fmt.Errorf("xdp: load objects: %w", err)
	}

	// Even when the spec matched, a stamped schema version that differs means
	// the on-disk maps were written by an incompatible build — recreate them.
	var ver uint32
	if lerr := e.objs.SchemaVersion.Lookup(uint32(0), &ver); lerr == nil && ver != 0 && ver != schemaVersion {
		e.objs.Close()
		if uerr := unlinkPins(pinDir); uerr != nil {
			return fmt.Errorf("xdp: unlink schema-mismatched pins: %w", uerr)
		}
		if err := loadBpfObjects(&e.objs, opts); err != nil {
			return fmt.Errorf("xdp: reload after schema bump: %w", err)
		}
	}
	_ = e.objs.SchemaVersion.Put(uint32(0), schemaVersion)
	return nil
}

func (e *XdpEnforcer) attachWithFallback() error {
	type attempt struct {
		name string
		flag link.XDPAttachFlags
	}
	attempts := []attempt{{"driver", link.XDPDriverMode}, {"generic", link.XDPGenericMode}}
	if !e.auto {
		attempts = []attempt{{modeName(e.mode), e.mode}}
	}

	var last error
	for _, a := range attempts {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   e.objs.XdpBanFunc,
			Interface: e.ifindex,
			Flags:     a.flag,
		})
		if err == nil {
			e.xdp, e.attached, e.curMode = l, true, a.name
			return nil
		}
		last = err
		// Another XDP program is already attached: retrying generic won't help,
		// and we must NOT clobber it. Fail open with an actionable message.
		if errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("xdp: another XDP program is already attached to %s; "+
				"detach it or set enforcer.xdp.enabled=false: %w", e.iface, err)
		}
		// EOPNOTSUPP / ENOTSUP => native unsupported; loop falls through to generic.
	}
	return fmt.Errorf("xdp: attach failed (tried native+generic) on %s: %w", e.iface, last)
}

// Ban inserts the source IP into the appropriate family map. duration/reason
// are ignored (expiry is the daemon's job, matching iptables/ipset). A panic
// inside the map mutation is recovered so it can never take the daemon down.
func (e *XdpEnforcer) Ban(ip net.IP, _ time.Duration, _ string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xdp ban panic: %v", r)
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()

	const one uint8 = 1
	if k4, ok := v4Key(ip); ok {
		if perr := e.objs.BannedV4.Put(k4, one); perr != nil {
			return fmt.Errorf("xdp: ban v4 %s: %w", ip, perr) // E2BIG (map full) surfaces here
		}
		return nil
	}
	k6, ok := v6Key(ip)
	if !ok {
		return fmt.Errorf("xdp: ban %v: not a valid IP", ip)
	}
	if perr := e.objs.BannedV6.Put(bpfIn6Key{Addr: k6}, one); perr != nil {
		return fmt.Errorf("xdp: ban v6 %s: %w", ip, perr)
	}
	return nil
}

func (e *XdpEnforcer) Unban(ip net.IP) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xdp unban panic: %v", r)
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()

	if k4, ok := v4Key(ip); ok {
		if derr := e.objs.BannedV4.Delete(k4); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("xdp: unban v4 %s: %w", ip, derr)
		}
		return nil
	}
	k6, ok := v6Key(ip)
	if !ok {
		return fmt.Errorf("xdp: unban %v: not a valid IP", ip)
	}
	if derr := e.objs.BannedV6.Delete(bpfIn6Key{Addr: k6}); derr != nil && !errors.Is(derr, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("xdp: unban v6 %s: %w", ip, derr)
	}
	return nil
}

// List returns the live contents of the kernel maps (a state view). This is
// what reconcile reads directly — it is NOT the user-facing ban list (that
// stays the iptables/DB view via the composite's member[0]).
func (e *XdpEnforcer) List() ([]action.BanEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var out []action.BanEntry
	var val uint8

	var k4 [4]byte
	it4 := e.objs.BannedV4.Iterate()
	for it4.Next(&k4, &val) {
		ip := make(net.IP, 4)
		copy(ip, k4[:])
		out = append(out, action.BanEntry{IP: ip.String()})
	}
	if err := it4.Err(); err != nil {
		return nil, err
	}

	var k6 bpfIn6Key
	it6 := e.objs.BannedV6.Iterate()
	for it6.Next(&k6, &val) {
		ip := make(net.IP, 16)
		copy(ip, k6.Addr[:])
		out = append(out, action.BanEntry{IP: ip.String()})
	}
	return out, it6.Err()
}

// MapEntries reports the live size of each family map (for /xdp/status and the
// near-saturation alert).
func (e *XdpEnforcer) MapEntries() (v4 int, v6 int, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var val uint8
	var k4 [4]byte
	it4 := e.objs.BannedV4.Iterate()
	for it4.Next(&k4, &val) {
		v4++
	}
	if err = it4.Err(); err != nil {
		return
	}
	var k6 bpfIn6Key
	it6 := e.objs.BannedV6.Iterate()
	for it6.Next(&k6, &val) {
		v6++
	}
	err = it6.Err()
	return
}

// Stats sums the per-CPU PASS/DROP counters the program maintains.
func (e *XdpEnforcer) Stats() (passed uint64, dropped uint64, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var perCPU []uint64
	if err = e.objs.Stats.Lookup(statPassed, &perCPU); err != nil {
		return
	}
	for _, v := range perCPU {
		passed += v
	}
	if err = e.objs.Stats.Lookup(statDropped, &perCPU); err != nil {
		return
	}
	for _, v := range perCPU {
		dropped += v
	}
	return
}

func (e *XdpEnforcer) Attached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attached
}

func (e *XdpEnforcer) Mode() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.curMode
}

// Close detaches the link (the program stops running) but leaves the maps
// pinned so bans survive a restart. This is also the SIGHUP kill-switch path.
func (e *XdpEnforcer) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var errs []error
	if e.xdp != nil {
		errs = append(errs, e.xdp.Close())
		e.xdp = nil
		e.attached = false
	}
	errs = append(errs, e.objs.Close())
	return errors.Join(errs...)
}

// isPinIncompatible reports whether a load error stems from a pinned map whose
// on-disk spec no longer matches the program's expectation.
func isPinIncompatible(err error) bool {
	return errors.Is(err, ebpf.ErrMapIncompatible)
}

// unlinkPins removes every pinned object under dir so the next load recreates
// them from scratch.
func unlinkPins(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		if rerr := os.Remove(filepath.Join(dir, ent.Name())); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
	}
	return nil
}

// writeProbe confirms the bpffs pin directory is actually writable before we
// attempt a load — gives a clear error instead of a confusing load failure
// when /sys/fs/bpf isn't mounted.
func writeProbe(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
