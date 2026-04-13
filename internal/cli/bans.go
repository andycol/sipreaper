package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func apiRequest(method, path string, body string) ([]byte, error) {
	url := apiAddr + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+getToken())
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func newBansCmd() *cobra.Command {
	var showAll bool
	cmd := &cobra.Command{
		Use:   "bans",
		Short: "List bans",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "/api/v1/bans"
			if showAll {
				path += "?status="
			}
			data, err := apiRequest("GET", path, "")
			if err != nil {
				return err
			}

			var bans []map[string]interface{}
			json.Unmarshal(data, &bans)
			for _, b := range bans {
				fmt.Printf("%-16s %-14s %-8s %s\n", b["IP"], b["Detector"], b["Status"], b["Reason"])
			}
			if len(bans) == 0 {
				fmt.Println("no bans found")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "show all bans including expired")
	return cmd
}

func newBanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ban <ip> [duration]",
		Short: "Manually ban an IP",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			duration := ""
			if len(args) > 1 {
				duration = args[1]
			}
			body := fmt.Sprintf(`{"ip": %q, "duration": %q}`, ip, duration)
			_, err := apiRequest("POST", "/api/v1/bans", body)
			if err != nil {
				return err
			}
			fmt.Printf("banned %s\n", ip)
			return nil
		},
	}
}

func newUnbanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unban <ip>",
		Short: "Unban an IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := apiRequest("DELETE", "/api/v1/bans/"+args[0], "")
			if err != nil {
				return err
			}
			fmt.Printf("unbanned %s\n", args[0])
			return nil
		},
	}
}
