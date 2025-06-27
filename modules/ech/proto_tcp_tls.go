package ech

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"

	"github.com/OmarTariq612/goech"
)

type tcpConn struct {
	proto            string
	domain           string
	port             uint
	connPrimer       func(*ConnDetails) error
	connTimeout      time.Duration
	configWithEch    *ftls.Config
	configWithoutEch *ftls.Config
}

func newTcpConn(domain string, port uint, echList []byte, protos []string, primer func(*ConnDetails) error) *tcpConn {
	return &tcpConn{
		proto:       protos[0],
		domain:      domain,
		port:        port,
		connPrimer:  primer,
		connTimeout: time.Second * 2,
		configWithEch: &ftls.Config{
			ServerName:                     domain,
			EncryptedClientHelloConfigList: echList,
			NextProtos:                     protos,
			InsecureSkipVerify:             true, // allows to use IPs as well
		},
		configWithoutEch: &ftls.Config{
			ServerName:         domain,
			NextProtos:         protos,
			InsecureSkipVerify: true,
		},
	}
}

func (c *tcpConn) Test(target string, traceHandshakeLatency bool) (*ConnDetails, error) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Warnf("tcp: Test call paniced for target: %s: %v\n", target, err)
		}
	}()

	var details = ConnDetails{
		Timestamp:                  time.Now(),
		Target:                     c.domain,
		Port:                       c.port,
		Protocol:                   c.proto,
		TLSHandshakeAnchorDuration: -1, // denotes unset
	}
	details.populateECHConfig(c.configWithEch.EncryptedClientHelloConfigList)

	// execute any primer function set for the protocol run.
	// the primer can be used to level networking related bias
	// such as cache fillings etc.
	if c.connPrimer != nil {
		if err := c.connPrimer(&details); err != nil {
			logrus.Warnf("primer function: %v", err)
			details.PrimerFailed = true
		}
	}

	host := net.JoinHostPort(c.domain, strconv.Itoa(int(c.port)))

	// tracing the TLS handshake latency requires to compare the latency from the
	// ECH connection with some base line latency. This base line latency is collected
	// by establishing a non-ECH connection through the same protocol and host and measuring
	// its latency.
	if traceHandshakeLatency {
		dialer := net.Dialer{
			Timeout:   c.connTimeout,
			KeepAlive: c.connTimeout,
			Resolver:  net.DefaultResolver,
		}

		anchor, retries, err := c.dialWithRetrys(&dialer, host, c.configWithoutEch)
		if err != nil { // all retries failed
			details.AnchorFailedConnAttempts = retries
			return &details, fmt.Errorf("%s: tcp anchor failed, retries: %d: %v", host, retries, err)
		}
		defer anchor.Close()

		if anchor.ConnectionState().ECHAccepted {
			return &details, fmt.Errorf("non ECH connection used for latency cmp indicates use of ECH")
		}

		details.AnchorPeerIP = IPFromTlsConn(anchor)
		details.TLSHandshakeAnchorDuration = anchor.TLSHandshakeDuration
	}

	// try to establish the actual ECH connection. If it fails we check for any
	// RetryConfig the server send back to us. Should there be any RetryConfig,
	// we will parse it and try to establish the connection again with the RetryConfig
	// echConn, err := ftls.DialWithDialer(&dialer, "tcp4", host, c.configWithEch)

	dialer := net.Dialer{
		Timeout:   c.connTimeout,
		KeepAlive: c.connTimeout,
		Resolver:  net.DefaultResolver,
	}
	echConn, retries, err := c.dialWithRetrys(&dialer, host, c.configWithEch)
	if err != nil {
		details.FailedConnAttempts = retries
		dialer.Timeout = c.connTimeout

		retryCfgs, ok := err.(*ftls.ECHRejectionError)
		if !ok { // other error, retries failed
			return &details, fmt.Errorf("%s: tcp ECH failed, retries: %d: %v ", host, retries, err)
		}

		if len(retryCfgs.RetryConfigList) == 0 {
			return &details, fmt.Errorf("%s: tcp server responded with empty RetryConfigs", host)
		}

		var parsedRetryList goech.ECHConfigList
		parsedRetryList, err = echFromjRetry(retryCfgs.RetryConfigList)
		if err != nil {
			return &details, fmt.Errorf("%s: tcp failed to parse RetryConfigs: %v", host, err)
		}

		details.RetryConfigs = mapTo(parsedRetryList, func(rt goech.ECHConfig) RetryConfig {
			return RetryConfig{
				EchVersion:  int(rt.Version),
				EchConfigID: int(rt.ConfigID),
				PublicName:  string(rt.RawPublicName),
				CipherSuites: mapTo(rt.CipherSuites, func(cs goech.HpkeSymmetricCipherSuite) string {
					return cs.String()
				}),
			}
		})
		parsed, err := parsedRetryList.MarshalBinary()
		if err != nil {
			return &details, fmt.Errorf("%s: failed to marshal RetryConfigs: %v", host, err)
		}
		details.populateECHConfig(parsed) // overwrite intial config with the one that worked

		c.configWithEch.EncryptedClientHelloConfigList = parsed
		echConn, retries, err = c.dialWithRetrys(&dialer, host, c.configWithEch)
		if err != nil {
			details.RetryConfigFailedConnAttempts = retries
			return &details, fmt.Errorf("%s: tcp connection failed with RetryConfigs: %v", host, err)
		}
	}
	defer echConn.Close()

	details.IP = IPFromTlsConn(echConn)
	details.Transport = TransportFromTlsConn(echConn)
	details.TLSVersion = VersionFromTlsConn(echConn)
	details.TLSHandshakeDuration = echConn.TLSHandshakeDuration
	details.ECHAccepted = EchAcceptedFromTlsConn(echConn)
	details.TLSHandshakeCompleted = HandshakeCompletedFromTlsConn(echConn)
	details.NegotiatedProto = ProtoFromTlsConn(echConn)
	details.NegotiatedCipher = CipherFromTlsConn(echConn)
	details.ClientHelloOuter = clientHelloOuterFromTlsConn(echConn)
	details.ClientHelloInner = clientHelloInnerFromTlsConn(echConn)
	details.ServerHello = serverHelloFromTlsConn(echConn)

	return &details, nil
}

const tcpMaxRetries = 2

func (c *tcpConn) dialWithRetrys(dialer *net.Dialer, host string, cfg *ftls.Config) (conn *ftls.Conn, retries int, err error) {
	for _ = range tcpMaxRetries {
		conn, err = ftls.DialWithDialer(dialer, "tcp4", host, cfg)
		if err == nil {
			return
		}
		_, ok := err.(*ftls.ECHRejectionError)
		if ok || errors.Is(err, context.Canceled) {
			return
		}

		retries += 1
		dialer.Timeout += time.Second
	}
	return
}
