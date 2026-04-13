package action

import (
	"net"
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
