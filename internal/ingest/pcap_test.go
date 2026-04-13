package ingest

import (
	"testing"
)

func TestBuildBPFFilter(t *testing.T) {
	tests := []struct {
		ports  []int
		custom string
		want   string
	}{
		{[]int{5060}, "", "udp port 5060"},
		{[]int{5060, 5061}, "", "udp port 5060 or udp port 5061"},
		{[]int{5060}, "host 10.0.0.1", "host 10.0.0.1"},
	}

	for _, tt := range tests {
		got := buildBPFFilter(tt.ports, tt.custom)
		if got != tt.want {
			t.Errorf("buildBPFFilter(%v, %q) = %q, want %q", tt.ports, tt.custom, got, tt.want)
		}
	}
}
