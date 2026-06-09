package cli

import (
	"github.com/andycol/sipreaper/internal/daemon"
	"github.com/spf13/cobra"
)

func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Start the SIPReaper daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return daemon.Run(configPath, apiToken)
		},
	}
}
