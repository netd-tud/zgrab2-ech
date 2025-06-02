package ech

import (
	"errors"
	"fmt"
	"iter"
	"net"

	ftls "github.com/netd-tud/zgrab2/gofork/tls"

	"github.com/OmarTariq612/goech"
)

type RetryConfig struct {
	EchVersion   int      `json:"ech_version"`
	EchConfigID  int      `json:"ech_config_id"`
	PublicName   string   `json:"ech_public_name"`
	CipherSuites []string `json:"ech_cipher_suites"`
}

type ConnDetails struct {
	Protocol                   string              `json:"protocol"`
	Error                      *string             `json:"error"`
	EchVersion                 int                 `json:"ech_version"`
	EchConfigID                int                 `json:"ech_config_id"`
	PublicName                 string              `json:"ech_public_name"`
	KemName                    uint16              `json:"kem_name"`
	LengthOfPreferenceConfigs  int                 `json:"len_preference_list"`
	CipherSuites               []string            `json:"ech_cipher_suites"`
	MaxNameLen                 int                 `json:"max_name_len"`
	RawExtensions              []byte              `json:"raw_extensions"`
	AlpnList                   []string            `json:"alpn_list"`
	IPv4Hints                  []string            `json:"ipv4_hints"`
	IPv6Hints                  []string            `json:"ipv6_hints"`
	IP                         *string             `json:"ip"`
	Transport                  *string             `json:"transport"`
	TLSVersion                 *string             `json:"tls_version"`
	TLSHandshakeDuration       int64               `json:"tls_handshake_duration_with_ech"`
	TLSHandshakeAnchorDuration int64               `json:"tls_handshake_duration_without_ech"`
	AnchorPeerIP               *string             `json:"tls_handshake_anchor_ip"`
	ECHAccepted                *bool               `json:"ech_accepted"`
	TLSHandshakeCompleted      *bool               `json:"tls_handshake_completed"`
	NegotiatedProto            *string             `json:"negotiated_protocol"`
	NegotiatedCipher           *string             `json:"negotiated_cipher"`
	RetryConfigs               []RetryConfig       `json:"retry_configs"`
	ClientHelloOuter           ftls.ClientHelloMsg `json:"client_hello_outer"`
	ClientHelloInner           ftls.ClientHelloMsg `json:"client_hello_inner"`
	ServerHello                ftls.ServerHelloMsg `json:"server_hello"`
}

func (c *ConnDetails) populate(cfg *config) {

	c.EchVersion = int(cfg.preferenceList[0].Version)
	c.EchConfigID = int(cfg.preferenceList[0].ConfigID)
	c.PublicName = string(cfg.preferenceList[0].RawPublicName)
	c.KemName = uint16(cfg.preferenceList[0].KEM)
	c.LengthOfPreferenceConfigs = len(cfg.preferenceList)
	c.CipherSuites = mapTo(
		cfg.preferenceList[0].CipherSuites,
		func(cs goech.HpkeSymmetricCipherSuite) string {
			return cs.String()
		},
	)
	c.MaxNameLen = int(cfg.preferenceList[0].MaxNameLength)
	c.RawExtensions = cfg.preferenceList[0].RawExtensions
	c.AlpnList = cfg.alpn
	c.IPv4Hints = cfg.ipv4hints
	c.IPv6Hints = cfg.ipv6hints
}

type ProtoTester interface {
	Test(timingValidation bool) (*ConnDetails, error)
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

func (pi *ProtoIter) Iter() iter.Seq2[*ConnDetails, error] {
	return func(yield func(*ConnDetails, error) bool) {
		for _, proto := range pi.protos {
			result, err := proto.Test(pi.timingValidation)

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
		return fmt.Errorf("tcp: tls (primer conn): failed to dial host(=%s): %v", host, err)
	}
	defer conn.Close()

	return nil
}

// query IP for target domain. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeWithDNSConn(domain string) error {
	_, err := net.LookupIP(domain)
	if err != nil {
		return fmt.Errorf("failed to resolve IP for domain: %v", err)
	}
	return nil
}

// establish TCP connection to the target. No information but the error is returned.
// based on measurements these function where needed to level / remove networking bias
// for measuring TLS handshake latencies.
func primeTCPConn(domain string) error {
	conn, err := net.Dial("tcp", net.JoinHostPort(domain, "80"))
	if err != nil {
		return fmt.Errorf("failed to open dummy tcp conn: %v", err)
	}
	defer conn.Close()

	return nil
}
