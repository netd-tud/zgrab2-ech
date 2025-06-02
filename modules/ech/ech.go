package ech

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/OmarTariq612/goech"
)

type config struct {
	// preferedRaw is the first listedd ECH config from
	// the first answers which has an ECH config set.
	// it can be used directly in the tls.Config as
	// EncrytedClientHello value
	preferedRaw []byte
	// preferenceList is the list of all ECH configs
	// in descending order of preference as set by the
	// HTTPS resource record. It contains only the preference
	// list of the first answer which has an ECH config parameter
	// set
	preferenceList    goech.ECHConfigList
	preferenceListRaw []byte
	alpn              []string
	ipv4hints         []string
	ipv6hints         []string
}

func overwriteConfigVersion(version *uint16) func(*goech.ECHConfig) {
	return func(e *goech.ECHConfig) {
		if version == nil {
			return
		}
		e.Version = *version
	}
}

func overwriteConfigID(id *uint8) func(*goech.ECHConfig) {
	return func(e *goech.ECHConfig) {
		if id == nil {
			return
		}
		e.ConfigID = *id
	}
}

func overwriteConfigPubName(pubName *string) func(*goech.ECHConfig) {
	return func(e *goech.ECHConfig) {
		if pubName == nil {
			return
		}
		e.RawPublicName = []byte(*pubName)
	}
}

func fromAnswers(answers []answer, overwrites ...func(*goech.ECHConfig)) (*config, error) {
	if len(answers) == 0 {
		return nil, fmt.Errorf("cannot parse zero length answer list")
	}

	var answerWithEch *answer
	for _, ans := range answers {
		// greedy search for first answer with ECH param set
		if ans.echConfig != "" {
			answerWithEch = &ans
			break
		}
	}

	if answerWithEch == nil {
		return nil, fmt.Errorf("no answer contains a ECH config string")
	}

	prefList, err := parseBase64EchConfigList(answerWithEch.echConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to parse base64 encoded ECH config: %w", err)
	}

	if len(prefList) == 0 {
		return nil, fmt.Errorf("parsed ECH config has length of zero")
	}

	for _, overwrite := range overwrites {
		overwrite(&prefList[0])
	}

	firstRaw, err := prefList[0].MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal prefered ECH config: %w", err)
	}

	rawList, err := prefList.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECH config list: %w", err)
	}

	return &config{
		preferedRaw:       firstRaw,
		preferenceList:    prefList,
		preferenceListRaw: rawList,
		alpn:              answerWithEch.alpn,
		ipv4hints:         answerWithEch.ipv4Hints,
		ipv6hints:         answerWithEch.ipv6Hints,
	}, nil

}

func fromOptionals(opts []string) (*config, error) {

	var err error
	var prefList goech.ECHConfigList
	var alpn []string
	var ipv4hints []string
	var ipv6hints []string

	// implies ech config was provided in optional fields.
	// use provided config
	if len(opts) > 0 {
		prefList, err = parseHexEncEchConfigList(opts[0])
		if err != nil {
			return nil, fmt.Errorf("unable to parse initial ech config: %w", err)
		}
	}

	// implies ALPN was passed as optional field
	if len(opts) > 1 {
		alpn = split(opts[1], ";")
	}

	// implies IPv4Hints were passed as optional field
	if len(opts) > 2 {
		ipv4hints = split(opts[2], ";")
	}

	// implies IPv6Hints were passed as optional field
	if len(opts) > 3 {
		ipv6hints = split(opts[3], ";")
	}

	b, err := prefList[0].MarshalBinary()
	if err != nil {
		return nil, err
	}

	rawList, err := prefList.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECH config list: %w", err)
	}

	return &config{
		preferedRaw:       b,
		preferenceList:    prefList,
		preferenceListRaw: rawList,
		alpn:              alpn,
		ipv4hints:         ipv4hints,
		ipv6hints:         ipv6hints,
	}, nil
}

func fromGreaseECH(domain string) (*config, error) {

	greased, err := greaseECH(domain, -1)
	if err != nil {
		return nil, err
	}

	b, err := greased.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var list goech.ECHConfigList = []goech.ECHConfig{greased}
	rawList, err := list.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ECH config list: %w", err)
	}

	return &config{
		preferedRaw:       b,
		preferenceList:    []goech.ECHConfig{greased},
		preferenceListRaw: rawList,
		alpn:              []string{},
		ipv4hints:         []string{},
		ipv6hints:         []string{},
	}, err

}

func parseBase64EchConfigList(echConfig string) (goech.ECHConfigList, error) {
	list, err := goech.ECHConfigListFromBase64(echConfig)
	if err != nil {
		return nil, err
	}
	return list, nil
}

func parseHexEncEchConfigList(hexStr string) (goech.ECHConfigList, error) {

	decodedConfig, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("unable to decode initial hex ech config: %w", err)
	}

	parsed, err := goech.UnmarshalECHConfigList(decodedConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to parse ECH config. Error while unmarshaling config: %w", err)
	}

	if len(parsed) == 0 {
		return nil, fmt.Errorf("unable to parse ECH config. No config found after parsing")
	}

	return parsed, nil
}

func split(str string, del string) []string {
	if str == "" {
		return nil
	}

	return strings.Split(str, del)
}
