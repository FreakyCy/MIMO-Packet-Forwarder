package cmd

import (
	"os"
	"text/template"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/FreakyCy/MIMO-Packet-Forwarder/internal/config"
)

const configTemplate = `[general]
# Log level
#
# debug=5, info=4, warning=3, error=2, fatal=1, panic=0
log_level={{ .General.LogLevel }}


[packet_multiplexer]
# Bind
#
# The interface:port on which the packet-multiplexer will bind for receiving
# data from the packet-forwarder (UDP data).
bind="{{ .PacketMultiplexer.Bind }}"
#
# Number of concentrator modules on gateway side. The MIMO-Packet-Multiplexer 
#will wait for this number of rxpk messages to send to backend, otherwise it will 
#take about 100ms to process the received message
concentrators=3
#
# This is the main gateway ID used for the communication with the backend software
maingatewayid="0101010101010101"
#
# Backends
#
# The backends to which the packet-multiplexer will forward the
# packet-forwarder UDP data.
#
# Example:
[[packet_multiplexer.backend]]
# # Host
# #
# # The host:IP of the backend.
host="192.16.1.5:1700"
#
# # Uplink only
#
# # This backend is for uplink only. It is not able to send downlink data
# # back to the gateways.
# uplink_only=false
# 
# # Gateway IDs
# #
# # The Gateway IDs to forward data for.
# gateway_ids = [
#   "0101010101010101",
#   "0202020202020202",
# ]
{{ range $index, $element := .PacketMultiplexer.Backends }}
[[packet_multiplexer.backend]]
host="{{ $element.Host }}"

uplink_only={{ $element.UplinkOnly }}

gateway_ids = [
{{ range $index, $element := $element.GatewayIDs -}}
  "{{ $element }}",
{{ end -}}
]
{{ end }}
`

var configCmd = &cobra.Command{
	Use:   "configfile",
	Short: "Print the MIMO-Packet-Forwarder configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		t := template.Must(template.New("config").Parse(configTemplate))
		err := t.Execute(os.Stdout, &config.C)
		if err != nil {
			return errors.Wrap(err, "execute config template error")
		}
		return nil
	},
}
