/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"strings"

	"github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/netd-tud/zgrab2/tools/greasy/ech"
	"github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

// tcpCmd represents the tcp command
var tcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "try establish grease connection to target using TCP + TLS",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			logrus.Errorf("Please provide a target domain $greasy tcp <target>")
			return
		}

		if err := run(strings.TrimSpace(args[0]), dialTCP); err != nil {
			logrus.Errorf("Failed: %v", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(tcpCmd)
}

const maxRetries = 2

func dialTCP(host string, config *tls.Config) (conn *tls.Conn, addr string, retries int, err error) {

	for _ = range maxRetries {
		conn, err = tls.Dial("tcp4", host, config)
		if err == nil {
			addr = conn.RemoteAddr().Network()
			return
		}

		// error, but recoverable! got retry configs to retry
		if configs := ech.RetryConfigs(err); configs != nil {
			return
		}

		if errors.Is(err, context.Canceled) {
			return
		}

		retries += 1
	}
	return
}
