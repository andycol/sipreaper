package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/andycol/sipreaper/internal/ingest"
	"github.com/spf13/cobra"
)

func newTestLineCmd() *cobra.Command {
	var fromStdin bool

	cmd := &cobra.Command{
		Use:   "test-line [LINE]",
		Short: "Run a log line through every parser and report what was extracted",
		Long: `Diagnose log lines that aren't being banned.

Pass a single line as the argument, or use --stdin to feed many lines:

	sipreaper test-line "WARNING:Rejected inbound carrier INVITE from non-whitelisted source 77.68.33.97 for DID 64300441975359019"

	tail -n 1000 /var/log/opensips.log | sipreaper test-line --stdin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromStdin {
				return runTestLineStdin(os.Stdin, os.Stdout)
			}
			if len(args) == 0 {
				return fmt.Errorf("provide a line as the argument or use --stdin")
			}
			line := strings.Join(args, " ")
			return printTestLineResult(os.Stdout, line)
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read lines from stdin")
	return cmd
}

func runTestLineStdin(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\n\r")
		if line == "" {
			continue
		}
		if err := printTestLineResult(out, line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func printTestLineResult(out io.Writer, line string) error {
	parser, evt := ingest.ParseLine(line)
	if evt == nil {
		fmt.Fprintf(out, "NO MATCH: %s\n", line)
		return nil
	}

	body := map[string]interface{}{
		"parser":        parser,
		"source_ip":     evt.SourceIP.String(),
		"method":        evt.Method,
		"from_user":     evt.FromUser,
		"to_user":       evt.ToUser,
		"response_code": evt.ResponseCode,
		"rejected":      evt.Rejected,
	}
	if evt.RejectReason != "" {
		body["reject_reason"] = evt.RejectReason
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(body)
}
