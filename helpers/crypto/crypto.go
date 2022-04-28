package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"

	"github.com/knox-networks/knox-go/signer"
	mb "github.com/multiformats/go-multibase"
	"github.com/tyler-smith/go-bip39"
)

type KeyPairs struct {
	MasterPublicKey  string
	MasterPrivateKey []byte

	AuthenticationPublicKey  string
	AuthenticationPrivateKey []byte

	CapabilityInvocationPublicKey  string
	CapabilityInvocationPrivateKey []byte

	CapabilityDelegationPublicKey  string
	CapabilityDelegationPrivateKey []byte

	AssertionMethodPublicKey  string
	AssertionMethodPrivateKey []byte
}

var MULTI_CODEC_PREFIX = []byte{0xed, 0x01}

const DID_PREFIX = "did:knox:"
const PROOF_TYPE = "Ed25519VerificationKey2020"

func GenerateKeyPair() (*KeyPairs, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return &KeyPairs{}, err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return &KeyPairs{}, err
	}

	public, private, err := ed25519.GenerateKey(strings.NewReader(mnemonic))
	if err != nil {
		return &KeyPairs{}, err
	}

	encodedPublic, err := mb.Encode(mb.Base58BTC, append(MULTI_CODEC_PREFIX, public...))
	if err != nil {
		return &KeyPairs{}, err
	}

	return &KeyPairs{
		MasterPublicKey:                encodedPublic,
		MasterPrivateKey:               private,
		AuthenticationPublicKey:        encodedPublic,
		AuthenticationPrivateKey:       private,
		CapabilityInvocationPublicKey:  encodedPublic,
		CapabilityInvocationPrivateKey: private,
		CapabilityDelegationPublicKey:  encodedPublic,
		CapabilityDelegationPrivateKey: private,
		AssertionMethodPublicKey:       encodedPublic,
		AssertionMethodPrivateKey:      private,
	}, nil

}

func (k *KeyPairs) Sign(relation signer.VerificationRelation, message []byte) ([]byte, error) {
	pvk := k.GetPrivateKey(relation)

	return ed25519.Sign(pvk, message), nil
}

func (k *KeyPairs) GetPrivateKey(relation signer.VerificationRelation) []byte {
	switch relation {
	case signer.Authentication:
		return k.AuthenticationPrivateKey
	case signer.CapabilityInvocation:
		return k.CapabilityInvocationPrivateKey
	case signer.CapabilityDelegation:
		return k.CapabilityDelegationPrivateKey
	case signer.AssertionMethod:
		return k.AssertionMethodPrivateKey
	default:
		return k.MasterPrivateKey
	}
}

func (k *KeyPairs) GetPublicKey(relation signer.VerificationRelation) ([]byte, error) {
	switch relation {
	case signer.Authentication:
		_, public, err := DecodePrefixed(k.AuthenticationPublicKey)
		return public, err
	case signer.CapabilityInvocation:
		_, public, err := DecodePrefixed(k.CapabilityInvocationPublicKey)
		return public, err
	case signer.CapabilityDelegation:
		_, public, err := DecodePrefixed(k.CapabilityDelegationPublicKey)
		return public, err
	case signer.AssertionMethod:
		_, public, err := DecodePrefixed(k.AssertionMethodPublicKey)
		return public, err
	default:
		_, public, err := DecodePrefixed(k.MasterPublicKey)
		return public, err
	}
}

func DecodePrefixed(encoded_key string) (mb.Encoding, []byte, error) {
	encoding, decoded, err := mb.Decode(encoded_key)

	if err != nil {
		return mb.Encoding(0), nil, err
	}

	prefix_less := bytes.TrimPrefix(decoded, MULTI_CODEC_PREFIX)

	return encoding, prefix_less, nil
}

func (k *KeyPairs) GetDid() string {
	return DID_PREFIX + k.MasterPublicKey
}
