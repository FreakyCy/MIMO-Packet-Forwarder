package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the MIMO-Packet-Forwarder version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}
