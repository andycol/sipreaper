package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	apiAddr  string
	apiToken string
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sipreaper",
		Short: "SIP attack detection and banning tool",
	}

	root.PersistentFlags().StringVar(&apiAddr, "api-addr", "http://127.0.0.1:8080", "API server address")
	root.PersistentFlags().StringVar(&apiToken, "api-token", "", "API bearer token (or set SIPREAPER_API_TOKEN)")

	root.AddCommand(newDaemonCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newBansCmd())
	root.AddCommand(newBanCmd())
	root.AddCommand(newUnbanCmd())
	root.AddCommand(newWhitelistCmd())
	root.AddCommand(newEventsCmd())
	root.AddCommand(newStatsCmd())

	return root
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func getToken() string {
	if apiToken != "" {
		return apiToken
	}
	return os.Getenv("SIPREAPER_API_TOKEN")
}
