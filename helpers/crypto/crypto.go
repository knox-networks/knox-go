package crypto

import (
	"bytes"
	"crypto/ed25519"
	"strings"

	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/signer"
	mb "github.com/multiformats/go-multibase"
	"github.com/tyler-smith/go-bip39"
)

const (
	DidPrefix        = "did:knox:"
	ProofType        = "Ed25519VerificationKey2020"
	KeyAgreementType = "X25519KeyAgreementKey2019"
)

var MultiCodecPrefix = []byte{0xed, 0x01}

type KeyPairs struct {
	Mnemonic         string
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

	KeyAgreementPublicKey  string
	KeyAgreementPrivateKey []byte
}

type cryptoManager struct {
}

type CryptoManager interface {
	GenerateKeyPair(mnemonic string) (*KeyPairs, error)
	GenerateMnemonic() (string, error)
}

func NewCryptoManager() CryptoManager {
	return &cryptoManager{}
}

func (c *cryptoManager) GenerateKeyPair(mnemonic string) (*KeyPairs, error) {

	public, private, err := ed25519.GenerateKey(strings.NewReader(mnemonic))
	if err != nil {
		return &KeyPairs{}, err
	}

	encodedPublic, err := mb.Encode(mb.Base58BTC, append(MultiCodecPrefix, public...))
	if err != nil {
		return &KeyPairs{}, err
	}

	return &KeyPairs{
		Mnemonic:                       mnemonic,
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
		KeyAgreementPublicKey:          encodedPublic,
		KeyAgreementPrivateKey:         private,
	}, nil

}

func (c *cryptoManager) GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return mnemonic, nil
}

func (k *KeyPairs) Sign(relation signer.VerificationRelation, message []byte) (*signer.SigningResponse, error) {
	pvk := k.GetPrivateKey(relation)
	return &signer.SigningResponse{
		ProofValue:         ed25519.Sign(pvk, message),
		ProofType:          model.ProofType,
		VerificationMethod: k.GetVerificationMethod(relation),
	}, nil
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

func (k *KeyPairs) GetDid() string {
	return DidPrefix + k.MasterPublicKey
}

func (k *KeyPairs) GetVerificationMethod(rel signer.VerificationRelation) string {

	switch rel {
	case signer.Authentication:
		return DidPrefix + k.MasterPublicKey + "#" + k.AuthenticationPublicKey
	case signer.CapabilityInvocation:
		return DidPrefix + k.MasterPublicKey + "#" + k.CapabilityInvocationPublicKey
	case signer.CapabilityDelegation:
		return DidPrefix + k.MasterPublicKey + "#" + k.CapabilityDelegationPublicKey
	case signer.AssertionMethod:
		return DidPrefix + k.MasterPublicKey + "#" + k.AssertionMethodPublicKey
	default:
		return DidPrefix + k.MasterPublicKey
	}

}

func DecodePrefixed(encoded_key string) (mb.Encoding, []byte, error) {
	encoding, decoded, err := mb.Decode(encoded_key)

	if err != nil {
		return mb.Encoding(0), nil, err
	}

	prefix_less := bytes.TrimPrefix(decoded, MultiCodecPrefix)

	return encoding, prefix_less, nil
}
