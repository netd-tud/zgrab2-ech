package ech

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/quic"
)

type quicConn struct {
	domain           string
	connPrimer       func() error
	connTimeout      time.Duration
	configWithEch    *quic.Config
	configWithoutEch *quic.Config
}

func newQuicConn(domain string, rawEch []byte, primer func() error) *quicConn {
	return &quicConn{
		domain:      domain,
		connTimeout: time.Second * 10,
		connPrimer:  primer,
		configWithEch: &quic.Config{
			TLSConfig: &tls.Config{
				MinVersion:                     tls.VersionTLS13,
				ServerName:                     domain,
				EncryptedClientHelloConfigList: rawEch,
				NextProtos:                     []string{"h3"},
			},
		},
		configWithoutEch: &quic.Config{
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: domain,
				NextProtos: []string{"h3"},
			},
		},
	}
}

func (c *quicConn) Test(withValidation bool) (*ConnDetails, error) {

	// NOTE: measurements show that if we only perform one request with ECH and one without
	// ECH enabled that what ever request is made first takes a significant amount of time
	// longer than the subsequent request. Assumption is caching, hence, we perform a dummy
	// request initially which we ignore before doing the actual two requests
	_, err := c.listenAndDial(c.connTimeout, c.domain, c.configWithoutEch)
	if err != nil {
		errO := fmt.Errorf("unable to dial QUIC dummy conn to %s: %v", c.domain, err)
		errOut := errO.Error()
		return &ConnDetails{Protocol: "h3", Error: &errOut}, errO
	}

	connECH, err := c.listenAndDial(c.connTimeout, c.domain, c.configWithEch)
	if err != nil {
		errO := fmt.Errorf("unable to dial QUIC conn to %s: %v", c.domain, err)
		errOut := errO.Error()
		return &ConnDetails{Protocol: "h3", Error: &errOut}, errO
	}

	var tlsHandshakeDurationAnchor int64 = -1 // denotes invalid result
	var anchorPeerIP *string = nil
	if withValidation {
		// since we are also measuring how long the TLS handshake took
		// we need some sort of anchor to compare the measurement against to.
		// Thus, we measure the TLS handshake duration without ECH enabled.

		connNoECH, err := c.listenAndDial(c.connTimeout, c.domain, c.configWithoutEch)
		if err != nil {
			// don't lose the information of the successful connection from before
			// and only log the error
			logrus.Warnf("failed to open QUIC conneciton w/o ECH enabled as timing anchor: %v", err)
		} else {
			if connNoECH.TLS != nil && connNoECH.TLS.Conn != nil {
				tlsHandshakeDurationAnchor = connNoECH.TLS.Conn.TLSHandshakeDuration
				if peerIp, _, err := net.SplitHostPort(connNoECH.PeerAddr.String()); err == nil {
					anchorPeerIP = &peerIp
				}
			}
		}
	}

	qConn := connECH.TLS
	tlsConn := qConn.Conn

	ip, _, err := net.SplitHostPort(connECH.PeerAddr.String())
	if err != nil {
		ip = connECH.PeerAddr.String()
	}

	transport := "udp"
	return &ConnDetails{
		Protocol:                   "h3",
		IP:                         &ip,
		Transport:                  &transport, //NOTE: tlsConn.NetConn is nil (really not sure why)
		TLSVersion:                 versionFromTlsConn(tlsConn),
		TLSHandshakeDuration:       tlsConn.TLSHandshakeDuration,
		TLSHandshakeAnchorDuration: tlsHandshakeDurationAnchor,
		AnchorPeerIP:               anchorPeerIP,
		ECHAccepted:                echAcceptedFromTlsConn(tlsConn),
		TLSHandshakeCompleted:      handshakeCompletedFromTlsConn(tlsConn),
		NegotiatedProto:            protoFromTlsConn(tlsConn),
		NegotiatedCipher:           cipherFromTlsConn(tlsConn),
		ClientHelloOuter:           clientHelloOuterFromTlsConn(tlsConn),
		ClientHelloInner:           clientHelloInnerFromTlsConn(tlsConn),
		ServerHello:                serverHelloFromTlsConn(tlsConn),
	}, nil
}

func (c *quicConn) listenAndDial(timeout time.Duration, domain string, config *quic.Config) (*quic.Conn, error) {

	// NOTE: previously listening on 127.0.0.1 worked for QUIC connections. However,
	// after seeing repeatted failed QUIC connections, turns out localhost can not be used??
	// Haven't found evidence in the x/net/quic package yet. Can only confirm so
	//
	// Listen on random (and available) port
	listener, err := quic.Listen("udp", ":0", nil)
	if err != nil {
		return nil, fmt.Errorf("unable to start quic listener: %w", err)
	}
	defer listener.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := listener.Dial(ctx, "udp", net.JoinHostPort(domain, "443"), config)
	if err != nil {
		// try to increase the timeout by x2
		if err == context.DeadlineExceeded {
			logrus.Warnf("[%s] quic connection timeout(=%dsec) from local(=%s) exeeded. Trying with timeout=%dsec", domain, int(timeout.Seconds()), listener.LocalAddr().String(), int(2*timeout.Seconds()))
			extendedCtx, extendedCancel := context.WithTimeout(context.Background(), timeout*2)
			defer extendedCancel()

			extendedConn, extendedErr := listener.Dial(extendedCtx, "udp", net.JoinHostPort(domain, "443"), config)
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
