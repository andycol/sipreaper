package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon status",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiRequest("GET", "/api/v1/status", "")
			if err != nil {
				return err
			}

			var resp map[string]interface{}
			json.Unmarshal(data, &resp)
			fmt.Printf("Status:      %s\n", resp["status"])
			fmt.Printf("Uptime:      %s\n", resp["uptime"])
			fmt.Printf("Active bans: %.0f\n", resp["active_bans"])
			return nil
		},
	}
}

func newStatsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show detection statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := apiRequest("GET", "/api/v1/stats", "")
			if err != nil {
				return err
			}

			var resp map[string]interface{}
			json.Unmarshal(data, &resp)
			fmt.Printf("Total bans:  %.0f\n", resp["total_bans"])
			fmt.Printf("Active bans: %.0f\n", resp["active_bans"])

			if byDet, ok := resp["bans_by_detector"].(map[string]interface{}); ok {
				fmt.Println("\nBans by detector:")
				for det, count := range byDet {
					fmt.Printf("  %-20s %.0f\n", det, count)
				}
			}
			return nil
		},
	}
}
