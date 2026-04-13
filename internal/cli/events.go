package cli

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

func newEventsCmd() *cobra.Command {
	var ip, detector, last string

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Query event history",
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if ip != "" {
				params.Set("ip", ip)
			}
			if detector != "" {
				params.Set("detector", detector)
			}
			if last != "" {
				params.Set("last", last)
			}

			path := "/api/v1/events"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}

			data, err := apiRequest("GET", path, "")
			if err != nil {
				return err
			}

			var events []map[string]interface{}
			json.Unmarshal(data, &events)
			for _, e := range events {
				fmt.Printf("%-20s %-16s %-10s %s\n",
					e["Timestamp"], e["SourceIP"], e["Method"], e["Source"])
			}
			if len(events) == 0 {
				fmt.Println("no events found")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&ip, "ip", "", "filter by IP")
	cmd.Flags().StringVar(&detector, "detector", "", "filter by detector")
	cmd.Flags().StringVar(&last, "last", "", "time window (e.g. 1h)")
	return cmd
}
