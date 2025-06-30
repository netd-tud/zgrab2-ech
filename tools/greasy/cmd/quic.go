/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netd-tud/zgrab2/gofork/quic"
)

// quicCmd represents the quic command
var quicCmd = &cobra.Command{
	Use:   "quic",
	Short: "try establish grease connection to target using QUIC",
	Run: func(cmd *cobra.Command, args []string) {
		listener, err := quic.Listen("udp4", ":0", nil)
		if err != nil {
			logrus.Errorf("Unable to start QUIC Listener: %v", err)
			return
		}

		dFn := dialQuic(listener)
		if err := run(strings.TrimSpace(args[0]), dFn); err != nil {
			logrus.Errorf("Failed: %v", err)
			return
		}
	},
}

func init() {
	rootCmd.AddCommand(quicCmd)
}

func dialQuic(listener *quic.Endpoint) dialFn {
	return func(host string, config *tls.Config) (conn *tls.Conn, addr string, retries int, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)

		for range maxRetries {

			c, e := listener.Dial(ctx, "udp4", host, &quic.Config{TLSConfig: config})
			err = e
			if err == nil {
				conn, addr, err = c.TLS.Conn, c.PeerAddr.String(), e
				cancel()
				return
			}

			var rejectErr *tls.ECHRejectionError
			ok := errors.As(err, &rejectErr)
			if ok || errors.Is(err, context.Canceled) {
				cancel()
				return
			}

			retries += 1
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), time.Second*3)
		}
		cancel()
		return
	}
}
