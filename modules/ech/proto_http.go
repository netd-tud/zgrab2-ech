package ech

// import (
// 	"bytes"
// 	"context"
// 	"crypto/tls"
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/http"
// 	"time"
// )

// type httpConn struct {
// 	proto                 string
// 	domain                string
// 	connTimeout           time.Duration
// 	clientEch             *http.Client
// 	clientNoEch           *http.Client
// 	clientDummy           *http.Client
// 	connDetailsEch        *ConnDetails
// 	rawECH                []byte
// 	tlsHandshakeAnchorIP  string
// 	tlsHandshakeAnchorDur int64
// }
//
// const defaultHttpTimeout = time.Second * 10
//
// func newHttpConn(domain string, rawEch []byte, proto string, timeout time.Duration) *httpConn {
// 	hconn := &httpConn{
// 		proto:       proto,
// 		domain:      domain,
// 		rawECH:      rawEch,
// 		connTimeout: timeout,
// 		clientEch: &http.Client{
// 			Transport: &http.Transport{
// 				ForceAttemptHTTP2: true, // TODO: unsure about this field
// 				MaxIdleConns:      100,
// 				DisableKeepAlives: true, // disable connection re-use
// 			},
// 			Timeout: timeout,
// 		},
// 		clientNoEch: &http.Client{
// 			Transport: &http.Transport{
// 				ForceAttemptHTTP2: true, // TODO: unsure about this field
// 				MaxIdleConns:      100,
// 				DisableKeepAlives: true, // disable connection re-use
// 			},
// 			Timeout: timeout,
// 		},
// 		clientDummy: &http.Client{
// 			Transport: &http.Transport{
// 				ForceAttemptHTTP2: true, // TODO: unsure about this field
// 				MaxIdleConns:      100,
// 				DisableKeepAlives: true, // disable connection re-use
// 				DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
// 					return tls.DialWithDialer(&net.Dialer{
// 						Timeout:   timeout,
// 						KeepAlive: timeout,
// 						DualStack: true, // technically not needed because deprecated
// 					}, network, addr, &tls.Config{
// 						ServerName: domain,
// 						NextProtos: []string{proto},
// 					})
// 				},
// 			},
// 			Timeout: timeout,
// 		},
// 	}
//
// 	transport := "http"
// 	// set client with ECH config
// 	hconn.SetDialTLSContext(hconn.clientEch.Transport.(*http.Transport), proto, transport, &tls.Config{
// 		EncryptedClientHelloConfigList: rawEch,
// 		ServerName:                     domain,
// 		NextProtos:                     []string{proto},
// 	})
//
// 	// set client without ECH config
// 	hconn.SetDialTLSContext(hconn.clientNoEch.Transport.(*http.Transport), proto, transport, &tls.Config{
// 		ServerName: domain,
// 		NextProtos: []string{proto},
// 	})
//
// 	return hconn
// }
//
// func (c *httpConn) SetDialTLSContext(tr *http.Transport, proto string, transport string, cfg *tls.Config) {
// 	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
// 		// NOTE: here we have access to the tls.Conn!
// 		// this means we can inject a pointer to a ConnDetail
// 		// into this function and populate only later
// 		// we can further enhance the details using the http response
// 		dialer := net.Dialer{
// 			Timeout:   c.connTimeout,
// 			KeepAlive: c.connTimeout,
// 			DualStack: true, // technically not needed because deprecated
// 		}
// 		conn, err := tls.DialWithDialer(&dialer, network, addr, cfg)
// 		if err != nil {
// 			return conn, err
// 		}
//
// 		ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
// 		if err != nil {
// 			ip = conn.RemoteAddr().String()
// 		}
//
// 		if c.connDetailsEch == nil {
// 			c.connDetailsEch = &ConnDetails{}
// 		}
// 		if cfg.EncryptedClientHelloConfigList == nil {
// 			c.tlsHandshakeAnchorDur = conn.TLSHandshakeDuration
// 			c.tlsHandshakeAnchorIP = ip
// 			return conn, err
// 		}
//
// 		// c.connDetailsEch = &ConnDetails{
// 		// 	Protocol:                   proto,
// 		// 	IP:                         &ip,
// 		// 	Transport:                  &transport,
// 		// 	TLSVersion:                 versionFromTlsConn(conn),
// 		// 	TLSHandshakeDuration:       conn.TLSHandshakeDuration,
// 		// 	TLSHandshakeAnchorDuration: -1,  // TODO: figure out how to solve this
// 		// 	AnchorPeerIP:               nil, // TODO: figure out how to solve this
// 		// 	ECHAccepted:                echAcceptedFromTlsConn(conn),
// 		// 	TLSHandshakeCompleted:      handshakeCompletedFromTlsConn(conn),
// 		// 	NegotiatedProto:            protoFromTlsConn(conn),
// 		// 	NegotiatedCipher:           cipherFromTlsConn(conn),
// 		// 	ClientHelloOuter:           clientHelloOuterFromTlsConn(conn),
// 		// 	ClientHelloInner:           clientHelloInnerFromTlsConn(conn),
// 		// 	ServerHello:                serverHelloFromTlsConn(conn),
// 		// }
// 		c.connDetailsEch.Protocol = proto
// 		c.connDetailsEch.IP = &ip
// 		c.connDetailsEch.Transport = &transport
// 		c.connDetailsEch.TLSVersion = versionFromTlsConn(conn)
// 		c.connDetailsEch.TLSHandshakeDuration = conn.TLSHandshakeDuration
// 		// c.connDetailsEch.TLSHandshakeAnchorDuration = -1 // TODO: figure out how to solve thi
// 		c.connDetailsEch.AnchorPeerIP = nil // TODO: figure out how to solve thi
// 		c.connDetailsEch.ECHAccepted = echAcceptedFromTlsConn(conn)
// 		c.connDetailsEch.TLSHandshakeCompleted = handshakeCompletedFromTlsConn(conn)
// 		c.connDetailsEch.NegotiatedProto = protoFromTlsConn(conn)
// 		c.connDetailsEch.NegotiatedCipher = cipherFromTlsConn(conn)
// 		c.connDetailsEch.ClientHelloOuter = clientHelloOuterFromTlsConn(conn)
// 		c.connDetailsEch.ClientHelloInner = clientHelloInnerFromTlsConn(conn)
// 		c.connDetailsEch.ServerHello = serverHelloFromTlsConn(conn)
//
// 		return conn, err
// 	}
//
// }
//
// func (c *httpConn) Test(withValidate bool) (ConnDetails, error) {
// 	// NOTE: measurements show that if we only perform one request with ECH and one without
// 	// ECH enabled that what ever request is made first takes a significant amount of time
// 	// longer than the subsequent request. Assumption is caching, hence, we perform a dummy
// 	// request initially which we ignore before doing the actual two requests.
// 	// QUESTION:
// 	// Should the dummy request be made with or without ECH enabled?
// 	// If we make a dummy request with ECH enabled we might trigger
// 	// caching actions on the client-facing server...
// 	// _, _ = c.doRequest(c.connTimeout, 0)
//
// 	// _, err := net.Dial("tcp", net.JoinHostPort(c.domain, "80"))
// 	// if err != nil {
// 	// 	errO := fmt.Errorf("failed to open dummy tcp conn: %v", err)
// 	// 	errOut := errO.Error()
// 	// 	return ConnDetails{Protocol: c.proto, Error: &errOut}, errO
// 	// }
//
// 	dialer := net.Dialer{
// 		Timeout:   c.connTimeout,
// 		KeepAlive: c.connTimeout,
// 		DualStack: true, // technically not needed because deprecated
// 	}
//
// 	host := net.JoinHostPort(c.domain, "443")
// 	dummyConn, err := tls.DialWithDialer(&dialer, "tcp", host, &tls.Config{
// 		ServerName:                     c.domain,
// 		NextProtos:                     []string{c.proto},
// 		EncryptedClientHelloConfigList: c.rawECH,
// 	})
//
// 	if err != nil {
// 		errO := fmt.Errorf("tcp: tls (dummy conn): failed to dial host(=%s): %v", host, err)
// 		errOut := errO.Error()
// 		return ConnDetails{Protocol: c.proto, Error: &errOut}, errO
// 	}
// 	dummyConn.Close()
//
// 	// _, err := net.LookupIP(c.domain)
// 	// if err != nil {
// 	// 	errO := fmt.Errorf("failed to resolve IP for domain: %v", err)
// 	// 	errOut := errO.Error()
// 	// 	return ConnDetails{Protocol: c.proto, Error: &errOut}, errO
// 	// }
//
// 	// actual first request with ECH enabled
//
// 	// echRespBody, err := c.doRequest(c.connTimeout, 1)
// 	// if err != nil {
// 	// 	errPtr := err.Error()
// 	// 	return ConnDetails{Protocol: c.proto, Error: &errPtr}, err
// 	// }
//
// 	if withValidate {
// 		// subsequent request without ECH enabled to validate
// 		// tls handshake time
// 		noEchRespBody, err := c.doRequest(c.connTimeout, 2)
// 		if err != nil {
// 			if c.connDetailsEch == nil {
// 				return ConnDetails{}, nil
// 			}
// 			return *c.connDetailsEch, err
// 		}
// 		kv := bytes.Split(noEchRespBody, []byte("\n"))
// 		colocation, fl, _ := parseCloudflareTrace(kv)
//
// 		// after the http request without ECH enabled has returned we can update the
// 		// ConnDetails with the validation information
// 		c.connDetailsEch.AnchorCfColocation = colocation
// 		c.connDetailsEch.AnchorCfFl = fl
// 		c.connDetailsEch.AnchorPeerIP = &c.tlsHandshakeAnchorIP
// 		c.connDetailsEch.TLSHandshakeAnchorDuration = c.tlsHandshakeAnchorDur
// 	}
//
// 	echRespBody, err := c.doRequest(c.connTimeout, 1)
// 	if err != nil {
// 		errPtr := err.Error()
// 		return ConnDetails{Protocol: c.proto, Error: &errPtr}, err
// 	}
//
// 	// parse relevant information from response body such as
// 	// loc,coloc fields
// 	kv := bytes.Split(echRespBody, []byte("\n"))
// 	colocation, fl, sni := parseCloudflareTrace(kv)
// 	c.connDetailsEch.CfColocation = colocation
// 	c.connDetailsEch.CfInstanceFl = fl
// 	c.connDetailsEch.CfSNI = sni
//
// 	return *c.connDetailsEch, nil
// }
//
// func parseCloudflareTrace(kv [][]byte) (colocation, fl, sni *string) {
// 	if kv == nil {
// 		return
// 	}
//
// 	for _, line := range kv {
// 		if bytes.HasPrefix(line, []byte("colo=")) {
// 			if parts := bytes.Split(line, []byte("=")); len(parts) > 1 {
// 				tmp := string(parts[1])
// 				colocation = &tmp
// 			}
// 		}
// 		if bytes.HasPrefix(line, []byte("fl=")) {
// 			if parts := bytes.Split(line, []byte("=")); len(parts) > 1 {
// 				tmp := string(parts[1])
// 				fl = &tmp
// 			}
// 		}
// 		if bytes.HasPrefix(line, []byte("sni=")) {
// 			if parts := bytes.Split(line, []byte("=")); len(parts) > 1 {
// 				tmp := string(parts[1])
// 				sni = &tmp
// 			}
// 		}
// 	}
// 	return
// }
//
// func (c *httpConn) doRequest(timeout time.Duration, useClient int) ([]byte, error) {
// 	var err error
// 	var resp *http.Response
//
// 	ctx, cancel := context.WithTimeout(context.Background(), 2*timeout)
// 	defer cancel()
//
// 	// TODO: exec twice
// 	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s/cdn-cgi/trace", c.domain), nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("http: unable to create request for host(=%s): %v", c.domain, err)
// 	}
//
// 	if useClient == 1 {
// 		resp, err = c.clientEch.Do(req)
// 		if err != nil {
// 			return nil, fmt.Errorf("http: request to host(=%s) failed: %v", c.domain, err)
// 		}
// 	} else if useClient == 2 {
// 		resp, err = c.clientNoEch.Do(req)
// 		if err != nil {
// 			return nil, fmt.Errorf("http(no ech): request to host(=%s) failed: %v", c.domain, err)
// 		}
// 	} else {
// 		resp, err = c.clientDummy.Do(req)
// 		if err != nil {
// 			return nil, fmt.Errorf("http(dummy client): request to host(=%s) failed: %v", c.domain, err)
// 		}
// 		resp.Body.Close()
// 		return nil, nil
// 	}
//
// 	defer resp.Body.Close()
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		// TODO: nicer if we somehow indicate that this failed??
// 		return []byte{}, nil
// 	}
//
// 	return body, nil
// }
