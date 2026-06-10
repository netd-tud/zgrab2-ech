package ech

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"time"

	"github.com/netd-tud/zgrab2/gofork/quic"
	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/OmarTariq612/goech"
)

type RetryConfig struct {
	EchVersion   int      `json:"ech_version"`
	EchConfigID  int      `json:"ech_config_id"`
	PublicName   string   `json:"ech_public_name"`
	CipherSuites []string `json:"ech_cipher_suites"`
	PublicKey    string   `json:"ech_public_key"`
}

type ConnDetails struct {
	Timestamp                     time.Time           `json:"timestamp"`
	Target                        string              `json:"target"`
	Protocol                      string              `json:"protocol"`
	Port                          uint                `json:"port"`
	Primer                        string              `json:"conn_primer"`
	PrimerFailed                  bool                `json:"conn_primer_failed"`
	Error                         *string             `json:"error"`
	FailedConnAttempts            int                 `json:"failed_connection_attempts"`
	RetryConfigFailedConnAttempts int                 `json:"retry_configs_failed_connection_attempts"`
	AnchorFailedConnAttempts      int                 `json:"anchor_failed_connection_attempts"`
	EchVersion                    int                 `json:"ech_version"`
	EchConfigID                   int                 `json:"ech_config_id"`
	PublicName                    string              `json:"ech_public_name"`
	KemName                       uint16              `json:"ech_kem_name"`
	LengthOfPreferenceConfigs     int                 `json:"ech_config_len"`
	CipherSuites                  []string            `json:"ech_cipher_suites"`
	MaxNameLen                    int                 `json:"ech_max_name_len"`
	RawExtensions                 []byte              `json:"ech_raw_extensions"`
	AlpnList                      []string            `json:"alpn_list"`
	IPv4Hints                     []string            `json:"ipv4_hints"`
	IPv6Hints                     []string            `json:"ipv6_hints"`
	IP                            *string             `json:"ip"`
	Transport                     *string             `json:"transport"`
	TLSVersion                    *string             `json:"tls_version"`
	TLSHandshakeDuration          int64               `json:"tls_handshake_duration_with_ech"`
	TLSHandshakeAnchorDuration    int64               `json:"tls_handshake_duration_without_ech"`
	TLSCertificateMatch           *bool               `json:"tls_certificate_match"`
	AnchorPeerIP                  *string             `json:"tls_handshake_anchor_ip"`
	ECHAccepted                   *bool               `json:"accepted_ech"`
	TLSHandshakeCompleted         *bool               `json:"tls_handshake_completed"`
	TimeToFirstByte               int64               `json:"ttfb"`
	AnchorTimeToFirstByte         int64               `json:"anchor_ttfb"`
	NegotiatedProto               *string             `json:"negotiated_protocol"`
	NegotiatedCipher              *string             `json:"negotiated_cipher"`
	RetryConfigs                  []RetryConfig       `json:"retry_configs"`
	ClientHelloOuter              ftls.ClientHelloMsg `json:"client_hello_outer"`
	ClientHelloInner              ftls.ClientHelloMsg `json:"client_hello_inner"`
	ServerHello                   ftls.ServerHelloMsg `json:"server_hello"`
	AnchoServerHello              ftls.ServerHelloMsg `json:"anchor_server_hello"`
}

func (c *ConnDetails) populateECHConfig(rawList []byte) {
	cfgList, err := goech.UnmarshalECHConfigList(rawList)
	if err != nil {
		logrus.Warnf("populateECHConfig: unable to unmarshal list: %v\n", err)
		return
	}

	if len(cfgList) <= 0 {
		logrus.Warnf("populateECHConfig: list has zero ECH configs!\n")
		return
	}

	cfg := cfgList[0]

	c.EchVersion = int(cfg.Version)
	c.EchConfigID = int(cfg.ConfigID)
	c.PublicName = string(cfg.RawPublicName)
	c.KemName = uint16(cfg.KEM)
	c.LengthOfPreferenceConfigs = len(cfgList)
	c.CipherSuites = mapTo(
		cfg.CipherSuites,
		func(cs goech.HpkeSymmetricCipherSuite) string {
			return cs.String()
		},
	)
	c.MaxNameLen = int(cfg.MaxNameLength)
	c.RawExtensions = cfg.RawExtensions
}

func (c *ConnDetails) populateHTTPSRR(cfg *config) {
	c.AlpnList = cfg.alpn
	c.IPv4Hints = cfg.ipv4hints
	c.IPv6Hints = cfg.ipv6hints
}

type ProtoTester interface {
	Test(target string, timingValidation bool) (*ConnDetails, error)
}

type ProtoIter struct {
	protos           []ProtoTester
	errors           []error
	remaining        int
	timingValidation bool
}

func newProtoIter(timingValidation bool) *ProtoIter {
	return &ProtoIter{
		protos:           []ProtoTester{},
		errors:           []error{},
		remaining:        0,
		timingValidation: timingValidation,
	}
}

func (pi *ProtoIter) Append(protos ...ProtoTester) {
	pi.protos = append(pi.protos, protos...)
	pi.remaining += len(protos)
}

func (pi *ProtoIter) Iter(target string) iter.Seq2[*ConnDetails, error] {
	return func(yield func(*ConnDetails, error) bool) {
		for _, proto := range pi.protos {
			result, err := proto.Test(target, pi.timingValidation)

			pi.remaining -= 1

			if err != nil && pi.remaining == 0 {
				pi.errors = append(pi.errors, err)
				err = errors.Join(pi.errors...)
			}

			if !yield(result, err) {
				return
			}
		}
	}
}

func mapTo[F any, T any](original []F, fn func(F) T) []T {
	if original == nil || len(original) <= 0 {
		return nil
	}
	out := make([]T, len(original))
	for i, o := range original {
		out[i] = fn(o)
	}
	return out
}

// establish a QUIC connection to the target. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeWithQUICConn(domain string, cfg *ftls.Config, dialer *net.Dialer) error {
	var err error

	host := net.JoinHostPort(domain, "443")
	listener, err := quic.Listen("udp4", ":0", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	anchor, err := listener.Dial(ctx, "udp4", host, &quic.Config{
		TLSConfig: &ftls.Config{
			MinVersion:         ftls.VersionTLS13,
			ServerName:         domain,
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		return fmt.Errorf("primer: failed to open quic on port 443 to %s: %v", domain, err)
	}
	defer anchor.Close()

	return nil
}

// establish a TLS connection to the target. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeWithTLSConn(domain string, cfg *ftls.Config, dialer *net.Dialer) error {
	var conn *ftls.Conn
	var err error

	host := net.JoinHostPort(domain, "443")
	if dialer == nil {
		conn, err = ftls.Dial("tcp", host, cfg)
	} else {
		conn, err = ftls.DialWithDialer(dialer, "tcp", host, cfg)
	}

	if err != nil {
		return fmt.Errorf("primer: failed to open tcp/tls on port 443 to %s: %v", domain, err)
	}
	defer conn.Close()

	return nil
}

// query IP for target domain. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeWithDNSConn(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	_, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return fmt.Errorf("primer: failed to query IP for %s: %v", domain, err)
	}
	return nil
}

// establish TCP connection to the target. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeWithTCPConn(domain string) error {
	conn, err := net.Dial("tcp", net.JoinHostPort(domain, "80"))
	if err != nil {
		return fmt.Errorf("primer: failed to open tcp on port 80 to %s: %v", domain, err)
	}
	defer conn.Close()

	return nil
}
