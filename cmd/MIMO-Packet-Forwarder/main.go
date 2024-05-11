package main

import "github.com/FreakyCy/MIMO-Packet-Forwarder/cmd/MIMO-Packet-Forwarder/cmd"

var version string // set by the compiler

func main() {
	cmd.Execute(version)
}
