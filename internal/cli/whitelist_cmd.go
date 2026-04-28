package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newWhitelistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whitelist",
		Short: "Manage IP whitelist",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiRequest("GET", "/api/v1/whitelist", "")
			if err != nil {
				return err
			}

			var entries []map[string]interface{}
			json.Unmarshal(data, &entries)
			for _, e := range entries {
				fmt.Printf("%-20s %-10s %s\n", e["IPCIDR"], e["Source"], e["Comment"])
			}
			if len(entries) == 0 {
				fmt.Println("no whitelist entries")
			}
			return nil
		},
	}

	cmd.AddCommand(newWhitelistAddCmd())
	cmd.AddCommand(newWhitelistRemoveCmd())
	return cmd
}

func newWhitelistAddCmd() *cobra.Command {
	var comment string
	var clearBan bool
	cmd := &cobra.Command{
		Use:   "add <ip>",
		Short: "Add IP to whitelist",
		Long: `Add an IP or CIDR to the dynamic whitelist.

If the IP is currently banned, the daemon refuses with HTTP 409 to avoid the
silent foot-gun of whitelisting an IP whose ban (and firewall rule) is still
in place. Pass --clear-ban to atomically expire the ban + remove the
firewall rule + add the whitelist entry.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := fmt.Sprintf(`{"ip": %q, "comment": %q, "clear_ban": %t}`, args[0], comment, clearBan)
			_, err := apiRequest("POST", "/api/v1/whitelist", body)
			if err != nil {
				return err
			}
			fmt.Printf("whitelisted %s", args[0])
			if clearBan {
				fmt.Printf(" (any existing ban cleared)")
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&comment, "comment", "", "comment for this entry")
	cmd.Flags().BoolVar(&clearBan, "clear-ban", false, "if the IP is currently banned, clear it before whitelisting")
	return cmd
}

func newWhitelistRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ip>",
		Short: "Remove IP from whitelist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := apiRequest("DELETE", "/api/v1/whitelist/"+args[0], "")
			if err != nil {
				return err
			}
			fmt.Printf("removed %s from whitelist\n", args[0])
			return nil
		},
	}
}
