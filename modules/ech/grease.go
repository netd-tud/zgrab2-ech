package ech

import (
	"crypto/rand"
	"fmt"

	"github.com/OmarTariq612/goech"
	"github.com/cloudflare/circl/hpke"
)

func greaseECH(domain string, overWriteConfigID int) (goech.ECHConfig, error) {
	var configID []byte = make([]byte, 1)

	if overWriteConfigID >= 0 && overWriteConfigID < 255 { // user provided a config-id
		configID = []byte{uint8(overWriteConfigID)}
	} else {
		if n, err := rand.Read(configID); err != nil || n != 1 {
			return goech.ECHConfig{}, fmt.Errorf("Unable to generate random config ID byte (read %d bytes): %v\n", n, err)
		}
	}

	pubKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		return goech.ECHConfig{}, fmt.Errorf("Unable to generate HPKE KEM_X25519_HKDP_SHA256 key pair as random public key for GREASE ECH config: %v", err)
	}

	// generate GREASE ECH config
	echConfig := goech.ECHConfig{
		PublicKey:     pubKey,
		Version:       0xfe0d, // 65037
		ConfigID:      uint8(configID[0]),
		RawPublicName: []byte(domain),
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

		MaxNameLength: 0,
		RawExtensions: nil,
	}

	return echConfig, nil
}

func echFromjRetry(retryConfigList []byte) (goech.ECHConfigList, error) {
	parsed, err := goech.UnmarshalECHConfigList(retryConfigList)
	if err != nil {
		return nil, fmt.Errorf("Returned retry configs from server is invalid: %v", err)
	}
	if len(parsed) <= 0 {
		return nil, fmt.Errorf("Returned retry configs from server are empty")
	}

	return parsed, nil
}
