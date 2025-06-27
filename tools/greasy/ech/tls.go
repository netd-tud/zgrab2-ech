package ech

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
	"github.com/netd-tud/zgrab2/gofork/tls"
	"github.com/sirupsen/logrus"
)

func Grease(publicName string, opts ...func(*goech.ECHConfig)) (goech.ECHConfig, error) {

	pubKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return goech.ECHConfig{}, fmt.Errorf("Unable to generate HPKE KEM_X25519_HKDP_SHA256 key pair as random public key for GREASE ECH config: %v", err)
	}

	var configID = make([]byte, 1)
	if n, err := rand.Read(configID); err != nil || n != 1 {
		return goech.ECHConfig{}, fmt.Errorf("Unable to generate random config ID byte (read %d bytes): %v\n", n, err)
	}

	greased := goech.ECHConfig{
		PublicKey:     pubKey,
		Version:       0xfe0d, // 65037
		ConfigID:      uint8(configID[0]),
		RawPublicName: []byte(publicName),
		KEM:           hpke.KEM_X25519_HKDF_SHA256,
		CipherSuites: []goech.HpkeSymmetricCipherSuite{
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES128GCM},
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_AES256GCM},
			{KDF: hpke.KDF_HKDF_SHA256, AEAD: hpke.AEAD_ChaCha20Poly1305},

			{KDF: hpke.KDF_HKDF_SHA384, AEAD: hpke.AEAD_AES128GCM},
			{KDF: hpke.KDF_HKDF_SHA384, AEAD: hpke.AEAD_AES256GCM},
			{KDF: hpke.KDF_HKDF_SHA384, AEAD: hpke.AEAD_ChaCha20Poly1305},

			{KDF: hpke.KDF_HKDF_SHA512, AEAD: hpke.AEAD_AES128GCM},
			{KDF: hpke.KDF_HKDF_SHA512, AEAD: hpke.AEAD_AES256GCM},
			{KDF: hpke.KDF_HKDF_SHA512, AEAD: hpke.AEAD_ChaCha20Poly1305},
		},

		MaxNameLength: uint8(len(publicName)),
		RawExtensions: nil,
	}

	for _, opt := range opts {
		opt(&greased)
	}

	return greased, nil
}

func WithConfigID(id int) func(*goech.ECHConfig) {
	return func(config *goech.ECHConfig) {
		if id < 0 || id > 255 {
			return
		}
		config.ConfigID = uint8(id)
	}
}
func WithVersion(vers uint16) func(*goech.ECHConfig) {
	return func(config *goech.ECHConfig) {
		config.Version = vers
	}
}

func TLS(domain string, cfg goech.ECHConfig, opts ...func(*tls.Config)) (*tls.Config, error) {

	rawEch, err := cfg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Unable to binary marshal ECH config: %v", err)
	}

	config := &tls.Config{
		ServerName:                     domain,
		EncryptedClientHelloConfigList: rawEch,
	}

	for _, opt := range opts {
		opt(config)
	}

	return config, nil
}

func WithMinVersion(vers uint16) func(*tls.Config) {
	return func(config *tls.Config) {
		config.MinVersion = vers
	}
}

func WithMaxVersion(vers uint16) func(*tls.Config) {
	return func(config *tls.Config) {
		config.MaxVersion = vers
	}
}

func WithKeyLogger(w io.Writer) func(*tls.Config) {
	return func(config *tls.Config) {
		config.KeyLogWriter = w
	}
}

func WithALPN(list string) func(*tls.Config) {
	return func(config *tls.Config) {
		config.NextProtos = strings.Split(list, ",")
	}
}

func WithInsecureSkipVerify(yes bool) func(*tls.Config) {
	return func(config *tls.Config) {
		config.InsecureSkipVerify = yes
	}
}

func Replace(config *tls.Config, ech goech.ECHConfig) error {

	raw, err := ech.MarshalBinary()
	if err != nil {
		return err
	}

	config.EncryptedClientHelloConfigList = raw
	return nil
}

func RetryConfigs(err error) *tls.ECHRejectionError {
	var rejection *tls.ECHRejectionError

	if !errors.As(err, &rejection) {
		return nil
	}

	return rejection
}

func LogEchConfigs(title string, configs ...goech.ECHConfig) {

	fmt.Fprintf(os.Stderr, "=== %s ===\n", title)
	for _, config := range configs {

		pubKey, err := config.PublicKey.MarshalBinary()
		if err != nil {
			logrus.Warnf("Unable to binary marshal public key for an ECH config: %v", err)
		}

		fmt.Fprintf(os.Stdout, "\x1b[0;33mECH Version     :\x1b[0m 0x%x (=%d)\n", config.Version, config.Version)
		fmt.Fprintf(os.Stdout, "\x1b[0;33mConfig ID       :\x1b[0m %d\n", config.ConfigID)
		fmt.Fprintf(os.Stdout, "\x1b[0;33mPublic Name     :\x1b[0m %s\n", string(config.RawPublicName))
		fmt.Fprintf(os.Stdout, "\x1b[0;33mCipher Suites   :\x1b[0m len=%d #1: %s\n", len(config.CipherSuites), config.CipherSuites[0])
		fmt.Fprintf(os.Stdout, "\x1b[0;33mPublic Key      :\x1b[0m %x\n", pubKey)
		fmt.Fprintf(os.Stdout, "\x1b[0;33mMax Name length :\x1b[0m %x\n", pubKey)
		fmt.Fprintf(os.Stdout, "\x1b[0;33mExtensions      :\x1b[0m %x\n", config.RawExtensions)

		fmt.Fprintf(os.Stdout, "\n")
	}
}
