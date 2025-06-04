package ech

import (
	"fmt"
	"net"
	"time"

	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"

	"github.com/OmarTariq612/goech"
)

type tcpConn struct {
	proto            string
	domain           string
	connPrimer       func(*ConnDetails) error
	connTimeout      time.Duration
	configWithEch    *ftls.Config
	configWithoutEch *ftls.Config
}

func newTcpConn(domain string, echList []byte, protos []string, primer func(*ConnDetails) error) *tcpConn {
	return &tcpConn{
		proto:       protos[0],
		domain:      domain,
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
		Domain:                     c.domain,
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

	dialer := net.Dialer{
		Timeout:   c.connTimeout,
		KeepAlive: c.connTimeout,
		DualStack: true, // technically not needed because deprecated
	}

	host := net.JoinHostPort(c.domain, "443")

	// tracing the TLS handshake latency requires to compare the latency from the
	// ECH connection with some base line latency. This base line latency is collected
	// by establishing a non-ECH connection through the same protocol and host and measuring
	// its latency.
	if traceHandshakeLatency {
		baseConn, err := ftls.DialWithDialer(&dialer, "tcp", host, c.configWithoutEch)
		if err != nil {
			return nil, fmt.Errorf("failed to open TCP conneciton w/o ECH enabled to (host=%s): %v", host, err)
		}
		defer baseConn.Close()

		if baseConn.ConnectionState().ECHAccepted {
			return nil, fmt.Errorf("non ECH connection used for latency cmp indicates use of ECH")
		}

		details.AnchorPeerIP = ipFromTlsConn(baseConn)
		details.TLSHandshakeAnchorDuration = baseConn.TLSHandshakeDuration
	}

	// try to establish the actual ECH connection. If it fails we check for any
	// RetryConfig the server send back to us. Should there be any RetryConfig,
	// we will parse it and try to establish the connection again with the RetryConfig
	echConn, err := ftls.DialWithDialer(&dialer, "tcp", host, c.configWithEch)
	if err != nil {
		if retryConfigs, ok := err.(*ftls.ECHRejectionError); ok {
			if len(retryConfigs.RetryConfigList) == 0 {
				return nil, fmt.Errorf("tcp: tls: RetryConfig: server provided empty RetryConfig")
			}

			var parsedRetryList goech.ECHConfigList
			parsedRetryList, err = echFromjRetry(retryConfigs.RetryConfigList)
			if err != nil {
				return nil, fmt.Errorf("tcp: tls: RetryConfig: failed to parse server provided RetryConfig: %v", err)
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
				return nil, fmt.Errorf("tcp: tls: RetryConfig: failed to marshal server provided RetryConfig: %v", err)
			}
			details.populateECHConfig(parsed) // overwrite intial config with the one that worked

			// retry ECH connection with parsed ECH RetryConfig
			c.configWithEch.EncryptedClientHelloConfigList = parsed
			echConn, err = ftls.DialWithDialer(&dialer, "tcp", host, c.configWithEch)
			if err != nil {
				return nil, fmt.Errorf("tcp: tls: RetryConfig: failed to host(=%q) with ECH RetryConfigs: %v", host, err)
			}
		} else {
			return nil, fmt.Errorf("tcp: tls (ECH): failed to dial host(=%s): %v", host, err)
		}
	}
	defer echConn.Close()

	details.IP = ipFromTlsConn(echConn)
	details.Transport = transportFromTlsConn(echConn)
	details.TLSVersion = versionFromTlsConn(echConn)
	details.TLSHandshakeDuration = echConn.TLSHandshakeDuration
	details.ECHAccepted = echAcceptedFromTlsConn(echConn)
	details.TLSHandshakeCompleted = handshakeCompletedFromTlsConn(echConn)
	details.NegotiatedProto = protoFromTlsConn(echConn)
	details.NegotiatedCipher = cipherFromTlsConn(echConn)
	details.ClientHelloOuter = clientHelloOuterFromTlsConn(echConn)
	details.ClientHelloInner = clientHelloInnerFromTlsConn(echConn)
	details.ServerHello = serverHelloFromTlsConn(echConn)

	return &details, nil
}
