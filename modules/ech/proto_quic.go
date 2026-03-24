package ech

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
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

func (c *quicConn) Test(target string, measureLatency bool) (*ConnDetails, error) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Warnf("quic: Test call paniced for target: %s: %v\n", target, err)
		}
	}()

	details := ConnDetails{
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

	host := net.JoinHostPort(c.domain, strconv.Itoa(int(c.port)))
	var anchorCertificate *x509.Certificate = nil
	if measureLatency {
		// since we are also measuring how long the TLS handshake took
		// we need some sort of anchor to compare the measurement against to.
		// Thus, we measure the TLS handshake duration without ECH enabled.

		listener, err := quic.Listen("udp4", ":0", nil)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close(context.Background())
		anchor, retries, err := c.dialWithRetries(listener, c.connTimeout, host, c.configWithoutEch)
		if err != nil {
			details.AnchorFailedConnAttempts = retries
			return &details, fmt.Errorf("%s: quic anchor failed, retries: %d: %v", host, retries, err)
		}
		defer anchor.Close()

		if anchor.TLS != nil && anchor.TLS.Conn != nil {
			details.TLSHandshakeAnchorDuration = anchor.TLS.Conn.TLSHandshakeDuration
			details.AnchorPeerIP = IPFromTlsConn(anchor.TLS.Conn)
		}
		anchorCertificate = anchor.TLS.ConnectionState().PeerCertificates[0]
	}

	listener, err := quic.Listen("udp4", ":0", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close(context.Background())
	echConn, retries, err := c.dialWithRetries(listener, c.connTimeout, host, c.configWithEch)
	if err != nil {
		details.FailedConnAttempts = retries

		details.TLSHandshakeInvalidECHDuration = echConn.TLS.Conn.TLSHandshakeDuration
		var rejectErr *ftls.ECHRejectionError
		ok := errors.As(err, &rejectErr)
		if !ok { // some unrecoverable error
			return &details, fmt.Errorf("%s: quic ECH failed, retries: %d: %v", host, retries, err)
		}

		if len(rejectErr.RetryConfigList) == 0 {
			return &details, fmt.Errorf("%s: quic server responded with empty RetryConfigs", host)
		}

		parsedRetryList, err := echFromjRetry(rejectErr.RetryConfigList)
		if err != nil {
			return &details, fmt.Errorf("%s: quic failed to parse RetryConfigs: %v", host, err)
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
			return &details, fmt.Errorf("%s: quic failed to marshal RetryConfigs: %v", host, err)
		}
		details.populateECHConfig(parsed)

		// retry ECH connection with parsed ECH RetryConfig
		c.configWithEch.TLSConfig.EncryptedClientHelloConfigList = parsed

		listener, err := quic.Listen("udp4", ":0", nil)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close(context.Background())
		echConn, retries, err = c.dialWithRetries(listener, c.connTimeout, host, c.configWithEch)
		if err != nil {
			details.RetryConfigFailedConnAttempts = retries
			return &details, fmt.Errorf("%s: quic connection failed with RetryConfigs: %v", host, err)
		}

		echConnCertificate := echConn.TLS.ConnectionState().PeerCertificates[0]
		if (anchorCertificate != nil) && (echConnCertificate != nil) {
			match := anchorCertificate == echConnCertificate
			details.TLSCertificateMatch = &match
		}

	}
	defer echConn.Close()

	qConn := echConn.TLS
	tlsConn := qConn.Conn

	ip, _, err := net.SplitHostPort(echConn.PeerAddr.String())
	if err != nil {
		ip = echConn.PeerAddr.String()
	}

	transport := "udp"

	details.IP = &ip
	details.Transport = &transport // NOTE: tlsConn.NetConn is nil (really not sure why
	details.TLSVersion = VersionFromTlsConn(tlsConn)
	details.TLSHandshakeDuration = tlsConn.TLSHandshakeDuration
	details.ECHAccepted = EchAcceptedFromTlsConn(tlsConn)
	details.TLSHandshakeCompleted = HandshakeCompletedFromTlsConn(tlsConn)
	details.NegotiatedProto = ProtoFromTlsConn(tlsConn)
	details.NegotiatedCipher = CipherFromTlsConn(tlsConn)
	details.ClientHelloOuter = clientHelloOuterFromTlsConn(tlsConn)
	details.ClientHelloInner = clientHelloInnerFromTlsConn(tlsConn)
	details.ServerHello = serverHelloFromTlsConn(tlsConn)

	return &details, nil
}

const quicMaxRetries = 2

func (c *quicConn) dialWithRetries(listener *quic.Endpoint, timeout time.Duration, host string, config *quic.Config) (conn *quic.Conn, retries int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for range quicMaxRetries {

		conn, err = listener.Dial(ctx, "udp4", host, config)
		if err == nil {
			return
		}

		var rejectErr *ftls.ECHRejectionError
		ok := errors.As(err, &rejectErr)
		if ok || errors.Is(err, context.Canceled) {
			return
		}
		retries += 1
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), timeout+time.Second)

	}
	return
}
