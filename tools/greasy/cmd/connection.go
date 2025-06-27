package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/OmarTariq612/goech"
	"github.com/netd-tud/zgrab2/gofork/tls"

	"github.com/netd-tud/zgrab2/tools/greasy/ech"
)

func getKeylogger() (io.Writer, error) {
	if keylogger == "" {
		return io.Discard, nil
	}

	file, err := os.Create(keylogger)
	if err != nil {
		return nil, fmt.Errorf("Unable to create master key file: %v", err)
	}

	return file, nil
}

type dialFn = func(host string, config *tls.Config) (*tls.Conn, int, error)

func run(target string, dial dialFn) error {

	keylogWriter, err := getKeylogger()
	if err != nil {
		return err
	}

	if pubName == "" {
		pubName = target
	}

	greased, err := ech.Grease(pubName,
		ech.WithConfigID(configID),
		ech.WithVersion(echVersion),
	)
	if err != nil {
		return err
	}

	ech.LogEchConfigs("Initial GREASE ECH", greased)

	config, err := ech.TLS(target, greased,
		ech.WithMinVersion(tlsMinVers),
		ech.WithMaxVersion(tlsMaxVers),
		ech.WithInsecureSkipVerify(insecureSkip),
		ech.WithKeyLogger(keylogWriter),
		ech.WithALPN(alpn),
	)
	if err != nil {
		return err
	}

	host := net.JoinHostPort(target, strconv.Itoa(int(port)))

	// init grease connection
	conn, _, err := dial(host, config)
	// looks like the server provided retry configs, try again!
	if rejectErr := ech.RetryConfigs(err); rejectErr != nil {
		retryConfigs, err := goech.UnmarshalECHConfigList(rejectErr.RetryConfigList)
		if err != nil {
			return fmt.Errorf("Unable to binary unmarshal server retry configs: %v", err)
		}

		if len(retryConfigs) <= 0 {
			return fmt.Errorf("Server for %s returned empty RetryConfigs!", host)
		}

		ech.LogEchConfigs(
			fmt.Sprintf("Server RetryConfigs (len=%d)", len(retryConfigs)),
			retryConfigs...,
		)

		first := retryConfigs[0]
		ech.LogEchConfigs("Choosing first RetryConfig for second attempt", first)

		if err := ech.Replace(config, first); err != nil {
			return fmt.Errorf("Unable to binary marshal picked RetryConfig: %v", err)
		}

		conn, _, err = dial(host, config)
		if err != nil {
			return fmt.Errorf("ECH connection with RetryConfig failed: %v", err)
		}
	} else {
		return err
	}

	pretty(host, conn)
	return nil
}

func pretty(host string, conn *tls.Conn) {
	fmt.Fprintf(os.Stdout, "=== %s: Connection Established, ECH Accepeted: %v ===\n", host, echAcceptedFromTlsConn(conn))
	fmt.Fprintf(os.Stdout, "\tIP Address           : %s\n", ipFromTlsConn(conn))
	fmt.Fprintf(os.Stdout, "\tTLS Handshake Latency: %s\n", latencyFromTlsConn(conn))
}

func ipFromTlsConn(conn *tls.Conn) string {
	if conn == nil || conn.NetConn() == nil {
		return "nil connection"
	}

	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return "invalid"
	}
	return host
}

func echAcceptedFromTlsConn(conn *tls.Conn) string {
	if conn == nil {
		return "nil connection"
	}

	if accepted := conn.ConnectionState().ECHAccepted; accepted {
		return "yes"
	}
	return "no"
}

func latencyFromTlsConn(conn *tls.Conn) string {
	if conn == nil {
		return "nil connection"
	}

	return fmt.Sprintf("%sms", strconv.Itoa(int(conn.TLSHandshakeDuration)))
}
