package action

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPTablesBanCommand(t *testing.T) {
	e := &IPTablesEnforcer{chain: "SIPREAPER"}
	args := e.banArgs(net.ParseIP("10.0.0.1"))
	expected := []string{"-A", "SIPREAPER", "-s", "10.0.0.1", "-j", "DROP"}

	if len(args) != len(expected) {
		t.Fatalf("args len = %d, want %d", len(args), len(expected))
	}
	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, arg, expected[i])
		}
	}
}

func TestIPTablesUnbanCommand(t *testing.T) {
	e := &IPTablesEnforcer{chain: "SIPREAPER"}
	args := e.unbanArgs(net.ParseIP("10.0.0.1"))
	expected := []string{"-D", "SIPREAPER", "-s", "10.0.0.1", "-j", "DROP"}

	if len(args) != len(expected) {
		t.Fatalf("args len = %d, want %d", len(args), len(expected))
	}
	for i, arg := range args {
		if arg != expected[i] {
			t.Errorf("arg[%d] = %q, want %q", i, arg, expected[i])
		}
	}
}

func TestIPTablesBanChecksBeforeAppending(t *testing.T) {
	logPath, _ := installFakeIPTables(t, `#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
if [ "$1" = "-C" ]; then exit 1; fi
if [ "$1" = "-A" ]; then exit 0; fi
exit 0
`)

	e := &IPTablesEnforcer{chain: "SIPREAPER"}
	if err := e.Ban(net.ParseIP("10.0.0.1"), 0, "test"); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}

	got := readCommandLog(t, logPath)
	want := []string{
		"-C SIPREAPER -s 10.0.0.1 -j DROP",
		"-A SIPREAPER -s 10.0.0.1 -j DROP",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("iptables commands = %v, want %v", got, want)
	}
}

func TestIPTablesBanSkipsAppendWhenRuleAlreadyExists(t *testing.T) {
	logPath, _ := installFakeIPTables(t, `#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
if [ "$1" = "-C" ]; then exit 0; fi
if [ "$1" = "-A" ]; then exit 42; fi
exit 0
`)

	e := &IPTablesEnforcer{chain: "SIPREAPER"}
	if err := e.Ban(net.ParseIP("10.0.0.1"), 0, "test"); err != nil {
		t.Fatalf("Ban() error: %v", err)
	}

	got := readCommandLog(t, logPath)
	want := []string{"-C SIPREAPER -s 10.0.0.1 -j DROP"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("iptables commands = %v, want %v", got, want)
	}
}

func TestIPTablesUnbanDeletesDuplicateRulesUntilAbsent(t *testing.T) {
	logPath, statePath := installFakeIPTables(t, `#!/bin/sh
echo "$@" >> "$IPTABLES_LOG"
count=$(cat "$IPTABLES_STATE" 2>/dev/null || echo 0)
case "$1" in
  -C)
    if [ "$count" -gt 0 ]; then exit 0; fi
    exit 1
    ;;
  -D)
    if [ "$count" -le 0 ]; then exit 1; fi
    echo $((count - 1)) > "$IPTABLES_STATE"
    exit 0
    ;;
esac
exit 0
`)
	if err := os.WriteFile(statePath, []byte("2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := &IPTablesEnforcer{chain: "SIPREAPER"}
	if err := e.Unban(net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("Unban() error: %v", err)
	}

	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(state)) != "0" {
		t.Fatalf("remaining duplicate count = %q, want 0; log=%v", strings.TrimSpace(string(state)), readCommandLog(t, logPath))
	}
}

func installFakeIPTables(t *testing.T, script string) (logPath string, statePath string) {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "iptables")
	logPath = filepath.Join(dir, "iptables.log")
	statePath = filepath.Join(dir, "iptables.state")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("IPTABLES_LOG", logPath)
	t.Setenv("IPTABLES_STATE", statePath)
	return logPath, statePath
}

func readCommandLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}
