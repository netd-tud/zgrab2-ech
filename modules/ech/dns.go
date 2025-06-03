package ech

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const defaultMaxRetries = 5

var defaultResolver = resolver{
	// resolvers:       []string{"8.8.8.8:53", "1.1.1.1:53"},
	resolvers:       []string{"141.30.1.1:53", "141.76.14.1:53"},
	currentResolver: 0,
	port:            "53",
	maxRetries:      defaultMaxRetries,
}

type resolver struct {
	resolvers       []string
	currentResolver int
	port            string
	maxRetries      int
}

type answer struct {
	alpn      []string
	ipv4Hints []string
	ipv6Hints []string
	echConfig string
}

const (
	svcbKeyAlpn     = "alpn"
	svcbKeyIpv4Hint = "ipv4hint"
	svcbKeyIpv6Hint = "ipv6hint"
	svcbKeyEch      = "ech"
)

// https queries the given resolver for the HTTPS resource
// record of the given domain.
// It returns all answeres found in the response or an
// error. An error is returned if all tries to query the
// record fail (defined by resolver.maxRetries).
//
// Answers are only checked for the following svcb keys values:
// - alpn
// - ipv4hint
// - ipv6hint
// - ech
//
// The returned answers are sorted by the order listed in the
// resource record
func (r resolver) https(domain string) ([]answer, error) {

	dnsAddr := r.resolvers[r.currentResolver%len(r.resolvers)]
	client := new(dns.Client)
	msg := new(dns.Msg)
	resp := new(dns.Msg)

	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	var err error

	for i := 0; i < r.maxRetries; i++ {
		resp, _, err = client.Exchange(msg, dnsAddr)
		if err != nil {
			// Timeout from the resolver, try backup resolver
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.currentResolver += 1
				nextAddr := r.resolvers[r.currentResolver%len(r.resolvers)]

				log.Warnf("DNS query timed out for resolver %s. Retrying with backup resolver: %s", dnsAddr, nextAddr)

				dnsAddr = nextAddr
				continue

			}
			log.Warnf("DNS query from %s -> %s failed for the %d time: %v", dnsAddr, domain, i, err)
			continue // retry until exhausted
		}

		break
	}

	if err != nil {
		return nil, fmt.Errorf("dns query failed: %w", err)
	}

	answers := []answer{}

	for _, a := range resp.Answer {

		if httpsRecord, ok := a.(*dns.HTTPS); ok {
			tmp := answer{}

			// Extract SVCB parameters
			for _, param := range httpsRecord.Value {
				switch param.Key().String() {
				case svcbKeyAlpn:
					tmp.alpn = strings.Split(param.String(), ",")
				case svcbKeyIpv4Hint:
					tmp.ipv4Hints = strings.Split(param.String(), ",")
				case svcbKeyIpv6Hint:
					tmp.ipv6Hints = strings.Split(param.String(), ",")
				case svcbKeyEch:
					tmp.echConfig = param.String()
				}

			}

			answers = append(answers, tmp)
		}
	}

	if len(answers) == 0 {
		return nil, fmt.Errorf("DNS responds has no answers")
	}

	log.Debugf("Answers: %+v\n", answers)

	return answers, nil
}
