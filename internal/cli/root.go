package cli

import (
	"fmt"
	"os"

	"github.com/andycol/sipreaper/internal/config"
	"github.com/spf13/cobra"
)

var (
	configPath string
	apiAddr    string
	apiToken   string
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "sipreaper",
		Short: "SIP attack detection and banning tool",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// If --api-addr was not explicitly set, try to read it from the config file
			if !cmd.Flags().Changed("api-addr") {
				addr := resolveAPIAddr()
				if addr != "" {
					apiAddr = addr
				}
			}
		},
	}

	root.PersistentFlags().StringVar(&configPath, "config", "/etc/sipreaper/config.yaml", "config file path")
	root.PersistentFlags().StringVar(&apiAddr, "api-addr", "", "API server address (reads from config if not set)")
	root.PersistentFlags().StringVar(&apiToken, "api-token", "", "API bearer token (or set SIPREAPER_API_TOKEN)")

	root.AddCommand(newDaemonCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newBansCmd())
	root.AddCommand(newBanCmd())
	root.AddCommand(newUnbanCmd())
	root.AddCommand(newWhitelistCmd())
	root.AddCommand(newEventsCmd())
	root.AddCommand(newStatsCmd())
	root.AddCommand(newTestLineCmd())

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

// resolveAPIAddr reads the config file to get the API listen address.
// Falls back to 127.0.0.1:8080 if the config can't be loaded.
func resolveAPIAddr() string {
	cfg, err := config.Load(configPath)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	return "http://" + cfg.API.Listen
}
