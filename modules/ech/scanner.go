package ech

import (
	"errors"
	"fmt"
	ftls "github.com/netd-tud/zgrab2/gofork/tls"
	"strings"
	"sync/atomic"
	"time"

	"github.com/netd-tud/zgrab2"
	log "github.com/sirupsen/logrus"
)

type Module struct{}

// Description implements zgrab2.ScanModule.
func (m *Module) Description() string {
	return "Check is EncryptedClientHello is supported by server"
}

// NewFlags implements zgrab2.ScanModule.
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

type Flags struct {
	zgrab2.BaseFlags

	ConnectionPrimer *string `long:"conn-primer" default:"none" description:"before each measurement connection perform either of (tcp-conn, dns-conn, tls-conn) to target domain"`
	Protocols        *string `long:"protos" default:"all" description:"measure only single (h1,h2,h3)"`
	UseGreaseECH     bool    `long:"greased" description:"don't query HTTPS RR for ECH config, but generate and use grease ECH for the connection"`

	MeasureHandshakeLatency bool `long:"measure-latency" description:"Additionally perform conn w/o ECH enabled to validate timing"`

	ConfigVersion *uint16 `long:"cfg-version" description:"overwrite the ech config version (effect global: all targets will use value)"`
	ConfigID      *uint8  `long:"cfg-id" description:"overwrite the ech config id (effect global: all targets will use value)"`
	ConfigPubName *string `long:"cfg-pub-name" description:"overwrite the ech config public name (effect global: all targets will use value)"`
}

func (f *Flags) Validate(args []string) error {
	return nil
}

func (f *Flags) Help() string {
	return ""
}

type Scanner struct {
	config       *Flags
	logicalClock atomic.Int64
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

	if target.Domain == "" {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, fmt.Errorf("input: scan target has no domain")
	}

	if strings.HasPrefix(target.Domain, "https://") {
		target.Domain = strings.TrimPrefix(target.Domain, "https://")
	}

	if strings.HasPrefix(target.Domain, "http://") {
		target.Domain = strings.TrimPrefix(target.Domain, "http://")
	}

	// the ECH config can be gathered by either:
	// 1: the scan input, where the base64 encoded ECH config is provided for each domain
	// 2: by querying the domains HTTPS resource record and parsing the base64 encoded echconfig
	// 3: or by generating a valid GREASE ECH
	echConfig, err := s.resolveECHConfig(target, s.config.UseGreaseECH)
	if err != nil {
		return zgrab2.SCAN_APPLICATION_ERROR, nil, fmt.Errorf("preparing ECH config: %w", err)
	}

	// this function will be called before each measurement
	var primerFunc = func() error { return nil }
	switch *s.config.ConnectionPrimer {
	case "tcp":
		primerFunc = func() error {
			return primeTCPConn(target.Domain)
		}
	case "tls":
		primerFunc = func() error {
			return primeWithTLSConn(target.Domain, &ftls.Config{ServerName: target.Domain}, nil)
		}
	case "dns":
		primerFunc = func() error {
			return primeWithDNSConn(target.Domain)
		}
	}

	var protoIter = newProtoIter(s.config.MeasureHandshakeLatency)

	switch *s.config.Protocols {
	case "none":
		protoIter.Append(
			newTcpConn(target.Domain, echConfig.preferenceListRaw, []string{"h1"}, primerFunc),
			newTcpConn(target.Domain, echConfig.preferenceListRaw, []string{"h2"}, primerFunc),
			newQuicConn(target.Domain, echConfig.preferenceListRaw, primerFunc),
		)
	case "h1":
		protoIter.Append(newTcpConn(target.Domain, echConfig.preferenceListRaw, []string{"h1"}, primerFunc))

	case "h2":
		protoIter.Append(newTcpConn(target.Domain, echConfig.preferenceListRaw, []string{"h2"}, primerFunc))
	case "h3":
		protoIter.Append(newQuicConn(target.Domain, echConfig.preferenceListRaw, primerFunc))
	}

	var results []ConnDetails = make([]ConnDetails, 0, 1)

	start := time.Now()
	for details, err := range protoIter.Iter() {
		if err != nil {
			log.Warnf("Tested protocol returned an error: %v", err)
			if errors.Is(err, ErrProtosExhausted) {
				return zgrab2.SCAN_APPLICATION_ERROR, nil, err
			}
			continue
		}

		details.populate(echConfig)
		results = append(results, *details)

	}

	if elapsed := time.Since(start).Milliseconds(); elapsed > 3000 {
		log.Infof("[TIMING] protocol iteration took > 3000ms: %dms", time.Since(start).Milliseconds())
	}

	return "success", results, nil
}

// resolveECHConfig generates or queries a working ECH config for the given ScanTarget.
// It is either parsed from optinals from the scanner's input, fetched from the HTTPS RR,
// or is generated as grease ECH.
func (s *Scanner) resolveECHConfig(target zgrab2.ScanTarget, greased bool) (*config, error) {
	if !greased {
		switch {
		case target.Optionals != nil && len(target.Optionals) > 0:
			return fromOptionals(target.Optionals)
		default:
			answers, err := defaultResolver.https(target.Domain)
			if err != nil {
				log.Errorf("[%s] failed to fetch HTTPS resource record: %v", target.Domain, err)
				return nil, fmt.Errorf("dns: unable to resolve HTTPS RR for target: %v", err)
			}

			return fromAnswers(answers,
				overwriteConfigVersion(s.config.ConfigVersion),
				overwriteConfigID(s.config.ConfigID),
				overwriteConfigPubName(s.config.ConfigPubName),
			)
		}
	}

	return fromGreaseECH(target.Domain)
}

func Register() {
	var mod Module

	_, err := zgrab2.AddCommand("ech", "measure EncrpytedClientHello extension in TLS1.3 (tcp/udp)", "", 443, &mod)
	if err != nil {
		log.Fatal(err)
	}
}
