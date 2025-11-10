package ech

import (
	"encoding/hex"

	"github.com/OmarTariq612/goech"
	"github.com/sirupsen/logrus"
)

type SerializableECHConfig struct {
	PublicKey     string                        `json:"ech_public_key"`
	Version       uint16                        `json:"ech_version"`
	ConfigID      uint8                         `json:"ech_config_id"`
	RawPublicName string                        `json:"ech_public_name"`
	KEM           string                        `json:"ech_kem"`
	CipherSuites  []SerializableHpkeCipherSuite `json:"ech_cipher_suites"`
	MaxNameLength uint8                         `json:"ech_max_name_length"`
	RawExtensions string                        `json:"ech_raw_extensions"`
}

type SerializableHpkeCipherSuite struct {
	Kdf  uint16 `json:"kdf"`
	Aead uint16 `json:"aead"`
}

// Convert ECHConfig to SerializableECHConfig
func ToSerializable(config goech.ECHConfig) SerializableECHConfig {
	// Convert cipher suites
	cipherSuites := make([]SerializableHpkeCipherSuite, len(config.CipherSuites))
	for i, cs := range config.CipherSuites {
		cipherSuites[i] = SerializableHpkeCipherSuite{
			Kdf:  uint16(cs.KDF),
			Aead: uint16(cs.AEAD),
		}
	}
	publicKey, err := config.PublicKey.MarshalBinary()
	if err != nil {
		logrus.Errorf("Unable to get PublicKey: %v", err)
	}

	return SerializableECHConfig{
		PublicKey:     hex.EncodeToString(publicKey),
		Version:       config.Version,
		ConfigID:      config.ConfigID,
		RawPublicName: string(config.RawPublicName),
		KEM:           config.KEM.Scheme().Name(), // Assuming KEM has String() method
		CipherSuites:  cipherSuites,
		MaxNameLength: config.MaxNameLength,
		RawExtensions: string(config.RawExtensions),
	}
}
