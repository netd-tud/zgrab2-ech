package ech

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"time"

	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"

	"github.com/OmarTariq612/goech"
)

type RetryConfig struct {
	EchVersion   int      `json:"ech_version"`
	EchConfigID  int      `json:"ech_config_id"`
	PublicName   string   `json:"ech_public_name"`
	CipherSuites []string `json:"ech_cipher_suites"`
}

type ConnDetails struct {
	Timestamp                  time.Time           `json:"timestamp"`
	Target                     string              `json:"target"`
	Protocol                   string              `json:"protocol"`
	Port                       uint                `json:"port"`
	Primer                     string              `json:"conn_primer"`
	PrimerFailed               bool                `json:"conn_primer_failed"`
	Error                      *string             `json:"error"`
	EchVersion                 int                 `json:"ech_version"`
	EchConfigID                int                 `json:"ech_config_id"`
	PublicName                 string              `json:"ech_public_name"`
	KemName                    uint16              `json:"ech_kem_name"`
	LengthOfPreferenceConfigs  int                 `json:"ech_config_len"`
	CipherSuites               []string            `json:"ech_cipher_suites"`
	MaxNameLen                 int                 `json:"ech_max_name_len"`
	RawExtensions              []byte              `json:"ech_raw_extensions"`
	AlpnList                   []string            `json:"alpn_list"`
	IPv4Hints                  []string            `json:"ipv4_hints"`
	IPv6Hints                  []string            `json:"ipv6_hints"`
	IP                         *string             `json:"ip"`
	Transport                  *string             `json:"transport"`
	TLSVersion                 *string             `json:"tls_version"`
	TLSHandshakeDuration       int64               `json:"tls_handshake_duration_with_ech"`
	TLSHandshakeAnchorDuration int64               `json:"tls_handshake_duration_without_ech"`
	AnchorPeerIP               *string             `json:"tls_handshake_anchor_ip"`
	ECHAccepted                *bool               `json:"accepted_ech"`
	TLSHandshakeCompleted      *bool               `json:"tls_handshake_completed"`
	NegotiatedProto            *string             `json:"negotiated_protocol"`
	NegotiatedCipher           *string             `json:"negotiated_cipher"`
	RetryConfigs               []RetryConfig       `json:"retry_configs"`
	ClientHelloOuter           ftls.ClientHelloMsg `json:"client_hello_outer"`
	ClientHelloInner           ftls.ClientHelloMsg `json:"client_hello_inner"`
	ServerHello                ftls.ServerHelloMsg `json:"server_hello"`
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
	remaining        int
	timingValidation bool
}

func newProtoIter(timingValidation bool) *ProtoIter {
	return &ProtoIter{
		protos:           []ProtoTester{},
		remaining:        0,
		timingValidation: timingValidation,
	}
}

func (pi *ProtoIter) Append(protos ...ProtoTester) {
	pi.protos = append(pi.protos, protos...)
	pi.remaining += len(protos)
}

var ErrProtosExhausted = errors.New("no more protocols to test - all failed")

func (pi *ProtoIter) Iter(target string) iter.Seq2[*ConnDetails, error] {
	return func(yield func(*ConnDetails, error) bool) {
		for _, proto := range pi.protos {
			result, err := proto.Test(target, pi.timingValidation)

			pi.remaining -= 1

			if err != nil && pi.remaining == 0 {
				err = errors.Join(ErrProtosExhausted, err)
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
