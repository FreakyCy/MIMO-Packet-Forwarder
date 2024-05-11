package cmd

import (
	"bytes"
	"io/ioutil"

	"github.com/FreakyCy/MIMO-Packet-Forwarder/internal/config"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var version string

var rootCmd = &cobra.Command{
	Use:   "MIMO-Packet-Forwarder",
	Short: "MIMO-Packet-Forwarder",
	Long: `MIMO-Packet-Forwarder sends MIMO-Packet-Forwarder data to multiple backends
	> documentation & support: https://github.com/FreakyCy/MIMO-Packet-Forwarder/
	> source & copyright information: https://github.com/brocaar/chirpstack-packet-multiplexer/`,
	RunE: run,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "path to configuration file (optional)")
	rootCmd.PersistentFlags().Int("log-level", 4, "debug=5, info=4, error=2, fatal=1, panic=0")

	viper.BindPFlag("general.log_level", rootCmd.PersistentFlags().Lookup("log-level"))

	viper.SetDefault("MIMO-Packet-Forwarder.bind", "0.0.0.0:1700")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
}

// Execute executes the root command.
func Execute(v string) {
	version = v
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func initConfig() {
	config.Version = version

	if cfgFile != "" {
		b, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			log.WithError(err).WithField("config", cfgFile).Fatal("error loading config file")
		}

		viper.SetConfigType("toml")
		if err := viper.ReadConfig(bytes.NewBuffer(b)); err != nil {
			log.WithError(err).WithField("config", cfgFile).Fatal("error loading config file")
		}
	} else {
		viper.SetConfigName("MIMO-Packet-Forwarder")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/./config/MIMO-Packet-Forwarder")
		viper.AddConfigPath("/etc/MIMO-Packet-Forwarder")
		if err := viper.ReadInConfig(); err != nil {
			switch err.(type) {
			case viper.ConfigFileNotFoundError:
				log.Warning("No configuration file found, using defaults.")
			default:
				log.WithError(err).Fatal("read configuration file error")
			}
		}
	}

	if err := viper.Unmarshal(&config.C); err != nil {
		log.WithError(err).Fatal("unmarshal config error")
	}

	log.SetLevel(log.Level(config.C.General.LogLevel))
}
