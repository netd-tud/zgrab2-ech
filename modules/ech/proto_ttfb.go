package ech

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/OmarTariq612/goech"
	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"
)

type ttfb struct {
	port             uint
	url              string
	echClient        *http.Client
	noEchClient      *http.Client
	echTlsCfg        *ftls.Config
	tlsCfg           *ftls.Config
	details          *ConnDetails
	TLSHSStart       time.Time
	TLSHSDone        time.Time
	AnchorTLSHSStart time.Time
	AnchorTLSHSDone  time.Time
}

func newTTFB(domain string, port uint, url string, rawEch []byte) *ttfb {
	ttfbC := &ttfb{
		port: port,
		url:  url,
		echTlsCfg: &ftls.Config{
			ServerName:                     domain,
			EncryptedClientHelloConfigList: rawEch,
			InsecureSkipVerify:             true,
		},
		tlsCfg: &ftls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		},
		echClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 3 * time.Second,
			},
		},
		noEchClient: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 3 * time.Second,
			},
		},
	}
	ttfbC.echClient.Transport.(*http.Transport).DialTLSContext = dialTLSCtxFunc(ttfbC, domain, port, ttfbC.echTlsCfg)
	ttfbC.noEchClient.Transport.(*http.Transport).DialTLSContext = dialTLSCtxFunc(ttfbC, domain, port, ttfbC.tlsCfg)
	return ttfbC
}

func dialTLSCtxFunc(ttfbC *ttfb, domain string, port uint, cfg *ftls.Config) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if ttfbC.details == nil {
			ttfbC.details = &ConnDetails{
				Protocol:  "ttfb",
				Target:    domain,
				Port:      port,
				Timestamp: time.Now(),
			}
		}

		dialer := ftls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: time.Second * 2,
			},
			Config: cfg,
		}

		var conn net.Conn
		var err error
		conn, err = dialer.DialContext(ctx, network, addr)
		if err != nil {
			// check for retry configs and try again
			if cfg.EncryptedClientHelloConfigList != nil {
				if retryConfigs, ok := err.(*ftls.ECHRejectionError); ok {
					parsedRetryList, err := echFromjRetry(retryConfigs.RetryConfigList)
					if err != nil {
						return conn, fmt.Errorf("ttfb: tls: RetryConfig: failed to parse server provided RetryConfig: %v", err)
					}
					ttfbC.details.RetryConfigs = mapTo(
						parsedRetryList,
						func(rt goech.ECHConfig) RetryConfig {
							publicKey, err := rt.PublicKey.MarshalBinary()
							if err != nil {
								logrus.Info("Unable to parse PublicKey")
							}
							return RetryConfig{
								EchVersion:  int(rt.Version),
								EchConfigID: int(rt.ConfigID),
								PublicName:  string(rt.RawPublicName),
								PublicKey:   hex.EncodeToString(publicKey),
								CipherSuites: mapTo(rt.CipherSuites, func(cs goech.HpkeSymmetricCipherSuite) string {
									return cs.String()
								}),
							}
						},
					)
					parsed, err := parsedRetryList.MarshalBinary()
					if err != nil {
						return conn, fmt.Errorf("ttfb: tls: RetryConfig: failed to marshal server provided RetryConfig: %v", err)
					}
					ttfbC.details.populateECHConfig(parsed) // overwrite intial config with the one that worked

					dialer.Config.EncryptedClientHelloConfigList = parsed
					conn, err = dialer.DialContext(ctx, network, addr)
				}
			} else {
				return conn, err
			}
		}

		if cfg.EncryptedClientHelloConfigList != nil && conn != nil {
			tlsConn, ok := conn.(*ftls.Conn)
			if !ok {
				logrus.Warn("ttfb: net.Conn not a *ftls.Conn\n")
				return nil, fmt.Errorf("ttfb: ftls dialer returned net.Conn which is not a *ftls.Conn")
			}
			ttfbC.TLSHSStart = tlsConn.TLSHandshakeStart
			ttfbC.TLSHSDone = tlsConn.TLSHandhshakeDone
			ttfbC.details.TLSHandshakeDuration = tlsConn.TLSHandshakeDuration
			ttfbC.details.IP = IPFromTlsConn(tlsConn)
			ttfbC.details.Transport = TransportFromTlsConn(tlsConn)
			ttfbC.details.TLSVersion = VersionFromTlsConn(tlsConn)
			ttfbC.details.ECHAccepted = EchAcceptedFromTlsConn(tlsConn)
			ttfbC.details.TLSHandshakeCompleted = HandshakeCompletedFromTlsConn(tlsConn)
			ttfbC.details.NegotiatedProto = ProtoFromTlsConn(tlsConn)
			ttfbC.details.NegotiatedCipher = CipherFromTlsConn(tlsConn)
			ttfbC.details.ClientHelloOuter = clientHelloOuterFromTlsConn(tlsConn)
			ttfbC.details.ClientHelloInner = clientHelloInnerFromTlsConn(tlsConn)
			ttfbC.details.ServerHello = serverHelloFromTlsConn(tlsConn)
			return conn, nil
		} else if cfg.EncryptedClientHelloConfigList == nil && conn != nil {
			tlsConn, ok := conn.(*ftls.Conn)
			if !ok {
				logrus.Warn("ttfb: net.Conn not a *ftls.Conn\n")
				return nil, fmt.Errorf("ttfb: ftls dialer returned net.Conn which is not a *ftls.Conn")
			}
			ttfbC.AnchorTLSHSStart = tlsConn.TLSHandshakeStart
			ttfbC.AnchorTLSHSDone = tlsConn.TLSHandhshakeDone
			ttfbC.details.TLSHandshakeAnchorDuration = tlsConn.TLSHandshakeDuration
			ttfbC.details.AnchorPeerIP = IPFromTlsConn(tlsConn)
			return conn, nil
		}

		return conn, err
	}
}

func (c *ttfb) Test(target string, measureLatency bool) (*ConnDetails, error) {
	if measureLatency {
		traceAnchor := &httptrace.ClientTrace{
			GotFirstResponseByte: func() {
				c.details.AnchorTimeToFirstByte = time.Now().Sub(c.AnchorTLSHSDone).Milliseconds()
			},
		}
		reqAnchor, err := reqWithTrace(target, c.port, c.url, traceAnchor)
		// _, err = c.noEchClient.Transport.RoundTrip(reqAnchor)
		_, err = c.noEchClient.Do(reqAnchor)
		if err != nil {
			return c.details, err
		}
		// NOTE: client is destroyed after success/failure, thus
		// no connection reuse, hence no need to spend CPU cycles
		// reading the response
		// _, _ = io.ReadAll(noEchResp.Body)
		// noEchResp.Body.Close()
	}

	traceECH := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			c.details.TimeToFirstByte = time.Now().Sub(c.TLSHSDone).Milliseconds()
		},
	}

	reqECH, err := reqWithTrace(target, c.port, c.url, traceECH)
	if err != nil {
		return c.details, err
	}

	// _, err = c.echClient.Transport.RoundTrip(reqECH)
	_, err = c.echClient.Do(reqECH)
	if err != nil {
		return c.details, err // RetryConfig checks within transport
	}
	// NOTE: client is destroyed after success/failure, thus
	// no connection reuse, hence no need to spend CPU cycles
	// reading the response
	// _, _ = io.ReadAll(echResp.Body)
	// echResp.Body.Close()

	return c.details, nil
}

func reqWithTrace(target string, port uint, url string, trace *httptrace.ClientTrace) (*http.Request, error) {
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("https://%s:%d%s", target, port, url),
		nil,
	)
	if err != nil {
		return nil, err
	}

	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), nil
}
