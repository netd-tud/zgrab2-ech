package ech

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/OmarTariq612/goech"
	"github.com/netd-tud/zgrab2/gofork/quic"
	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"
)

type quicConn struct {
	domain           string
	port             uint
	connPrimer       func(*ConnDetails) error
	connTimeout      time.Duration
	configWithEch    *quic.Config
	configWithoutEch *quic.Config
}

func newQuicConn(domain string, port uint, rawEch []byte, primer func(*ConnDetails) error) *quicConn {
	return &quicConn{
		domain:      domain,
		port:        port,
		connTimeout: time.Second * 2,
		connPrimer:  primer,
		configWithEch: &quic.Config{
			TLSConfig: &ftls.Config{
				MinVersion:                     ftls.VersionTLS13,
				ServerName:                     domain,
				EncryptedClientHelloConfigList: rawEch,
				NextProtos:                     []string{"h3"},
				InsecureSkipVerify:             true,
			},
		},
		configWithoutEch: &quic.Config{
			TLSConfig: &ftls.Config{
				MinVersion:         ftls.VersionTLS13,
				ServerName:         domain,
				NextProtos:         []string{"h3"},
				InsecureSkipVerify: true,
			},
		},
	}
}

func (c *quicConn) Test(target string, withValidation bool) (*ConnDetails, error) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Warnf("quic: Test call paniced for target: %s: %v\n", target, err)
		}
	}()

	var details = ConnDetails{
		Timestamp:                  time.Now(),
		Target:                     c.domain,
		Protocol:                   "quic",
		TLSHandshakeAnchorDuration: -1,
	}
	details.populateECHConfig(c.configWithEch.TLSConfig.EncryptedClientHelloConfigList)

	// execute any primer function set for the protocol run.
	// the primer can be used to level networking related bias
	// such as cache fillings etc.
	if c.connPrimer != nil {
		if err := c.connPrimer(&details); err != nil {
			logrus.Warnf("primer function: %v", err)
			details.PrimerFailed = true
		}
	}

	if withValidation {
		// since we are also measuring how long the TLS handshake took
		// we need some sort of anchor to compare the measurement against to.
		// Thus, we measure the TLS handshake duration without ECH enabled.

		connNoECH, err := c.listenAndDial(c.connTimeout, c.domain, c.port, c.configWithoutEch)
		if err != nil {
			// don't lose the information of the successful connection from before
			// and only log the error
			logrus.Warnf("failed to open QUIC conneciton w/o ECH enabled as timing anchor: %v", err)
		} else {
			if connNoECH.TLS != nil && connNoECH.TLS.Conn != nil {
				details.TLSHandshakeAnchorDuration = connNoECH.TLS.Conn.TLSHandshakeDuration
				if peerIp, _, err := net.SplitHostPort(connNoECH.PeerAddr.String()); err == nil {
					details.AnchorPeerIP = &peerIp
				}
			}
		}
	}

	connECH, err := c.listenAndDial(c.connTimeout, c.domain, c.port, c.configWithEch)
	if err != nil {
		var echErr *ftls.ECHRejectionError
		if errors.As(err, &echErr) {
			var parsedRetryList goech.ECHConfigList
			connECH, parsedRetryList, err = c.tryRetryConfig(echErr)
			if err != nil {
				return &details, fmt.Errorf("quic: ECH conn with retry config failed: %v", err)
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
				logrus.Warnf("quic: unable to marshal retry config: %v\n", err)
			} else {
				details.populateECHConfig(parsed)
			}

		} else {
			return &details, fmt.Errorf("quic: failed to dial host(=%s): %v", c.domain, err)
		}
	}
	defer connECH.Close()

	qConn := connECH.TLS
	tlsConn := qConn.Conn

	ip, _, err := net.SplitHostPort(connECH.PeerAddr.String())
	if err != nil {
		ip = connECH.PeerAddr.String()
	}

	transport := "udp"

	details.IP = &ip
	details.Transport = &transport //NOTE: tlsConn.NetConn is nil (really not sure why
	details.TLSVersion = versionFromTlsConn(tlsConn)
	details.TLSHandshakeDuration = tlsConn.TLSHandshakeDuration
	details.ECHAccepted = echAcceptedFromTlsConn(tlsConn)
	details.TLSHandshakeCompleted = handshakeCompletedFromTlsConn(tlsConn)
	details.NegotiatedProto = protoFromTlsConn(tlsConn)
	details.NegotiatedCipher = cipherFromTlsConn(tlsConn)
	details.ClientHelloOuter = clientHelloOuterFromTlsConn(tlsConn)
	details.ClientHelloInner = clientHelloInnerFromTlsConn(tlsConn)
	details.ServerHello = serverHelloFromTlsConn(tlsConn)

	return &details, nil
}

func (c *quicConn) listenAndDial(timeout time.Duration, domain string, port uint, config *quic.Config) (*quic.Conn, error) {

	// NOTE: previously listening on 127.0.0.1 worked for QUIC connections. However,
	// after seeing repeatted failed QUIC connections, turns out localhost can not be used??
	// Haven't found evidence in the x/net/quic package yet. Can only confirm so
	//
	// Listen on random (and available) port
	listener, err := quic.Listen("udp4", ":0", nil)
	if err != nil {
		return nil, fmt.Errorf("unable to start quic listener: %w", err)
	}
	defer listener.Close(context.Background())
	defer func() {
		if err := recover(); err != nil {
			logrus.Warnf("Quic panic for domain: %s:%d with: %v", domain, port, err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := listener.Dial(ctx, "udp4", net.JoinHostPort(domain, strconv.Itoa(int(port))), config)
	if err != nil {
		// try to increase the timeout by x2
		if err == context.DeadlineExceeded {
			logrus.Warnf("[%s] quic connection timeout(=%dsec) from local(=%s) exeeded. Trying with timeout=%dsec", domain, int(timeout.Seconds()), listener.LocalAddr().String(), int(2*timeout.Seconds()))
			extendedCtx, extendedCancel := context.WithTimeout(context.Background(), timeout*2)
			defer extendedCancel()

			extendedConn, extendedErr := listener.Dial(extendedCtx, "udp4", net.JoinHostPort(domain, "443"), config)
			if extendedErr != nil {
				return nil, fmt.Errorf("unable to dial quic connection even after extending timeout: %w", extendedErr)
			}
			extendedConn.Close()

			return extendedConn, nil
		}
		return nil, fmt.Errorf("unable to dial quic connection: %w", err)
	}

	// we are not doing anything with the conn, hence closing it directly is ok
	// since we have already captured everything we need
	conn.Close()

	return conn, nil
}

func (c *quicConn) tryRetryConfig(retryConfigs *ftls.ECHRejectionError) (*quic.Conn, goech.ECHConfigList, error) {
	if len(retryConfigs.RetryConfigList) == 0 {
		return nil, nil, fmt.Errorf("quic: RetryConfig: server provided empty RetryConfig")
	}

	parsedRetryList, err := echFromjRetry(retryConfigs.RetryConfigList)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: RetryConfig: failed to parse server provided RetryConfig: %v", err)
	}

	parsed, err := parsedRetryList.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("quic: RetryConfig: failed to marshal server provided RetryConfig: %v", err)
	}

	// retry ECH connection with parsed ECH RetryConfig
	c.configWithEch.TLSConfig.EncryptedClientHelloConfigList = parsed
	connECH, err := c.listenAndDial(c.connTimeout, c.domain, c.port, c.configWithEch)
	if err != nil {
		return nil, nil, fmt.Errorf("quic: RetryConfig: failed to host(=%q) with ECH RetryConfigs: %v", c.domain, err)
	}

	return connECH, parsedRetryList, nil
}
