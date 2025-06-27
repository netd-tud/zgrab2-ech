/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/spf13/cobra"
)

var (
	verbose   bool
	keylogger string

	port         uint
	alpn         string
	tlsMinVers   uint16
	tlsMaxVers   uint16
	insecureSkip bool

	configID   int
	echVersion uint16
	pubName    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "greasy",
	Short: "Perform greased ECH connection to a target (domain/IP)",
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.greasy.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.PersistentFlags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().StringVar(&alpn, "alpn", "http/1.1,h2,h3", "ALPN list send in the TLS ClientHello")
	rootCmd.PersistentFlags().StringVar(&pubName, "public-name", "", "custom ECH public name for initial grease ECH, default target domain")
	rootCmd.PersistentFlags().StringVar(&keylogger, "key-logger", "", "if set writes TLS master keys to specified file")
	rootCmd.PersistentFlags().IntVarP(&configID, "config-id", "", -1, "overwrite ECH config ID, -1 means choose random")
	rootCmd.PersistentFlags().Uint16Var(&echVersion, "ech-version", 0xfe0d, "overwrite ECH version")
	rootCmd.PersistentFlags().UintVarP(&port, "port", "p", 443, "port to use for TCP/TLS connection(s)")
	rootCmd.PersistentFlags().Uint16Var(&tlsMinVers, "tls-min-vers", tls.VersionTLS13, "minimal TLS version set in ClientHello")
	rootCmd.PersistentFlags().Uint16Var(&tlsMaxVers, "tls-max-vers", tls.VersionTLS13, "maximal TLS version set in ClientHello")
	rootCmd.PersistentFlags().BoolVar(&insecureSkip, "tls-insecure-skip-verify", false, "if set certificate checks on the client side are skipped")

}
