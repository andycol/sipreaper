package ingest

import (
	"strings"
	"testing"
)

// FuzzParseKamailioLine and FuzzParseOpenSIPSLine surface regex pathologies
// (catastrophic backtracking, panics, IP-parse panics) by feeding the parsers
// random/grown inputs. Run locally with:
//
//	go test -fuzz=FuzzParseOpenSIPSLine -fuzztime=30s ./internal/ingest/

func FuzzParseKamailioLine(f *testing.F) {
	seeds := []string{
		`Mar 27 10:15:30 sip1 kamailio[1234]: ERROR: auth: authentication failed for alice@example.com from 203.0.113.50`,
		`received REGISTER from 198.51.100.20:5060`,
		``,
		`!@#$%^&*()`,
		`from 999.999.999.999:5060`,
		strings.Repeat("a", 4096),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseKamailioLine(line)
	})
}

func FuzzParseOpenSIPSLine(f *testing.F) {
	seeds := []string{
		`Apr 28 11:02:14 sip2 opensips[4321]: WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019`,
		`failed to authenticate user from 1.2.3.4`,
		`received OPTIONS from 1.2.3.4:5060`,
		`INVITE from 1.2.3.4 forbidden`,
		``,
		`Rejected\nINVITE\n1.2.3.4`,
		strings.Repeat("Rejected ", 1000) + "INVITE 1.2.3.4",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = parseOpenSIPSLine(line)
	})
}
