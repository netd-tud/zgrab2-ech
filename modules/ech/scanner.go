package ech

import (
	"errors"
	"fmt"
	"strings"

	ftls "github.com/netd-tud/zgrab2/gofork/tls"

	"github.com/netd-tud/zgrab2"
	log "github.com/sirupsen/logrus"
)

type Module struct{}

// Description implements zgrab2.ScanModule.
func (m *Module) Description() string {
	return "Check whether EncryptedClientHello is supported by an endpoint"
}

// NewFlags implements zgrab2.ScanModule.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

type Flags struct {
	zgrab2.BaseFlags

	ConnectionPrimer *string `long:"conn-primer" default:"none" description:"before each measurement connection perform either of (tcp-conn, dns-conn, tls-conn) to target domain"`
	Protocols        *string `long:"protos" default:"h1,h2,h3" description:"comma separated list of protocols (h1,h2,h3)"`
	UseGreaseECH     bool    `long:"greased" description:"don't query HTTPS RR for ECH config, but generate and use grease ECH for the connection"`

	MeasureHandshakeLatency bool `long:"measure-latency" description:"Additionally perform conn w/o ECH enabled to validate timing"`

	ConfigVersion *uint16 `long:"cfg-version" description:"overwrite the ech config version (effect global: all targets will use value)"`
	ConfigID      *uint8  `long:"cfg-id" description:"overwrite the ech config id (effect global: all targets will use value)"`
	ConfigPubName *string `long:"cfg-pub-name" description:"overwrite the ech config public name (effect global: all targets will use value)"`

	Resolvers *string `long:"resolvers" description:"comma separated list of DNS resolver ip:port"`
}

func (f *Flags) Validate(args []string) error {
	return nil
}

func (f *Flags) Help() string {
	return ""
}

type Scanner struct {
	config *Flags
	protos []string
}

// NewScanner implements zgrab2.ScanModule.
func (m *Module) NewScanner() zgrab2.Scanner {
	return &Scanner{}
}

// GetName implements zgrab2.Scanner.
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger implements zgrab2.Scanner.
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Init implements zgrab2.Scanner.
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, ok := flags.(*Flags)
	if !ok {
		return zgrab2.ErrMismatchedFlags
	}

	s.config = f

	if resolvers := parseResolvers(*s.config.Resolvers); len(resolvers) > 0 {
		defaultResolver.setCustom(resolvers...)
	}

	s.protos = strings.Split(*s.config.Protocols, ",")

	return nil
}

// InitPerSender implements zgrab2.Scanner.
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// Protocol implements zgrab2.Scanner.
func (s *Scanner) Protocol() string {
	return "ech"
}

// Scan implements zgrab2.Scanner.
//
// Scan receives a single target (domain, optionals?) and tries to establish a tls
// connection using either http2 (tcp) or http3 (udp/quic) with the enabled encrypted client hello
// extension.
// It reports the same JSON structure on success and on failure (the later without any data besides
// the reason for the failure - if certain protocols failed (h2 | h3) the error will be located in the
// respective protocol object.
func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	if target.Domain == "" && target.IP.String() == "" {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, fmt.Errorf("input: scan target has no domain/IP")
	}

	var targetStr = target.Domain
	if target.IP.String() != "" && target.Domain == "" {
		targetStr = target.IP.String()
	}

	if strings.HasPrefix(target.Domain, "https://") {
		targetStr = strings.TrimPrefix(target.Domain, "https://")
	}

	if strings.HasPrefix(target.Domain, "http://") {
		targetStr = strings.TrimPrefix(target.Domain, "http://")
	}

	// the ECH config can be gathered by either:
	// 1: the scan input, where the base64 encoded ECH config is provided for each domain
	// 2: by querying the domains HTTPS resource record and parsing the base64 encoded echconfig
	// 3: or by generating a valid GREASE ECH
	targetConfig, err := s.resolveECHConfig(target, targetStr, s.config.UseGreaseECH)
	if err != nil {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, fmt.Errorf("preparing ECH config: %w", err)
	}

	// this function will be called before each measurement of a target
	// unless provided its a NOP. Can be used to mitigate certain timing issues
	var primerFunc = func(details *ConnDetails) error {
		details.Primer = "none"
		return nil
	}

	switch *s.config.ConnectionPrimer {
	case "tcp":
		primerFunc = func(details *ConnDetails) error {
			details.Primer = "tcp"
			return primeWithTCPConn(target.Domain)
		}
	case "tls":
		primerFunc = func(details *ConnDetails) error {
			details.Primer = "tls"
			return primeWithTLSConn(targetStr, &ftls.Config{ServerName: targetStr}, nil)
		}
	case "dns":
		primerFunc = func(details *ConnDetails) error {
			details.Primer = "dns"
			return primeWithDNSConn(targetStr)
		}
	}

	var protoIter = newProtoIter(s.config.MeasureHandshakeLatency)

	for _, proto := range s.protos {
		switch proto {
		case "h1", "h2":
			protoIter.Append(newTcpConn(
				targetStr,
				targetConfig.preferenceListRaw,
				[]string{proto},
				primerFunc,
			))
		case "h3":
			protoIter.Append(newQuicConn(
				targetStr,
				targetConfig.preferenceListRaw,
				primerFunc,
			))
		default:
			log.Warnf("unrecogniced protocol provided: don't know: %q\n", proto)
		}
	}

	var results []ConnDetails = make([]ConnDetails, 0, 1)

	for details, err := range protoIter.Iter(targetStr) {
		if err != nil {
			log.Warnf("Tested protocol returned an error: %v", err)
			if errors.Is(err, ErrProtosExhausted) {
				return zgrab2.SCAN_APPLICATION_ERROR, nil, err
			}
			continue
		}

		details.populateHTTPSRR(targetConfig)
		results = append(results, *details)

	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

// resolveECHConfig generates or queries a working ECH config for the given ScanTarget.
// It is either parsed from optinals from the scanner's input, fetched from the HTTPS RR,
// or is generated as grease ECH.
func (s *Scanner) resolveECHConfig(target zgrab2.ScanTarget, targetStr string, greased bool) (*config, error) {
	if !greased {
		switch {
		case target.Optionals != nil && len(target.Optionals) > 0:
			return fromOptionals(target.Optionals)
		default:
			answers, err := defaultResolver.https(targetStr)
			if err != nil {
				log.Errorf("[%s] failed to fetch HTTPS resource record: %v", targetStr, err)
				return nil, fmt.Errorf("dns: unable to resolve HTTPS RR for target: %v", err)
			}

			return fromAnswers(answers,
				overwriteConfigVersion(s.config.ConfigVersion),
				overwriteConfigID(s.config.ConfigID),
				overwriteConfigPubName(s.config.ConfigPubName),
			)
		}
	}

	return fromGreaseECH(targetStr)
}

func parseResolvers(resolvers string) []string {
	return strings.Split(resolvers, ",")
}

func Register() {
	var mod Module

	_, err := zgrab2.AddCommand("ech", "measure EncrpytedClientHello extension in TLS1.3 (tcp/udp)", "", 443, &mod)
	if err != nil {
		log.Fatal(err)
	}
}
