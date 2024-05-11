package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/FreakyCy/MIMO-Packet-Forwarder/internal/config"
	"github.com/FreakyCy/MIMO-Packet-Forwarder/internal/multiplexer"
)

var mp *multiplexer.Multiplexer

func run(cmd *cobra.Command, args []string) error {

	tasks := []func() error{
		setLogLevel,
		printStartMessage,
		setupMultiplexer,
	}

	for _, t := range tasks {
		if err := t(); err != nil {
			log.Fatal(err)
		}
	}

	sigChan := make(chan os.Signal)
	exitChan := make(chan struct{})
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	log.WithField("signal", <-sigChan).Info("signal received")
	go func() {
		log.Warning("stopping MIMO-Packet-Forwarder")
		if err := mp.Close(); err != nil {
			log.Fatal(err)
		}
		exitChan <- struct{}{}
	}()
	select {
	case <-exitChan:
	case s := <-sigChan:
		log.WithField("signal", s).Info("signal received, stopping immediately")
	}

	return nil
}

func setLogLevel() error {
	log.SetLevel(log.Level(uint8(config.C.General.LogLevel)))
	return nil
}

func printStartMessage() error {
	log.WithFields(log.Fields{
		"version": version,
		"docs":    "https://github.com/FreakyCy/MIMO-Packet-Forwarder",
	}).Info("starting MIMO-Packet-Forwarder")
	return nil
}

func setupMultiplexer() error {
	var err error
	mp, err = multiplexer.New(config.C.PacketMultiplexer)
	if err != nil {
		return errors.Wrap(err, "new multiplexer error")
	}

	return nil
}
