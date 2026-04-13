package cli

import (
	"github.com/andycol/sipreaper/internal/daemon"
	"github.com/spf13/cobra"
)

var configPath string

func newDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Start the SIPReaper daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Run(configPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "/etc/sipreaper/config.yaml", "config file path")
	return cmd
}
