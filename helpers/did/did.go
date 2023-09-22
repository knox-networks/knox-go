package did

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/knox-networks/knox-go/helpers/crypto"
	"github.com/knox-networks/knox-go/helpers/dataintegrity"
	"github.com/knox-networks/knox-go/helpers/dataintegrity/cryptosuite"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/signer"
	"strings"
)

const (
	urdna2015   = "URDNA2015"
	ed255192020 = "Ed25519Signature2020"
)

func CreateDidDocument(kps *crypto.KeyPairs) *model.DidDocument {
	return &model.DidDocument{
		Context: []string{"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1"},
		Id: kps.MasterPublicKey,
		Authentication: []model.KeyMaterial{
			{
				Id:                 kps.GetVerificationMethod(signer.Authentication),
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AuthenticationPublicKey,
			},
		},
		CapabilityInvocation: []model.KeyMaterial{
			{
				Id:                 kps.GetVerificationMethod(signer.CapabilityInvocation),
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityInvocationPublicKey,
			},
		},
		CapabilityDelegation: []model.KeyMaterial{
			{
				Id:                 kps.GetVerificationMethod(signer.CapabilityDelegation),
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityDelegationPublicKey,
			},
		},
		AssertionMethod: []model.KeyMaterial{
			{
				Id:                 kps.GetVerificationMethod(signer.AssertionMethod),
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AssertionMethodPublicKey,
			},
		},
		KeyAgreement: []model.KeyMaterial{
			{
				Id:                 kps.GetVerificationMethod(signer.KeyAgreement),
				Type:               crypto.KeyAgreementType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.KeyAgreementPublicKey,
			},
		},
	}
}

func GenerateDidDocumentProof(mnemonic string, did, didDoc string) (*dataintegrity.Proof, error) {
	signingMethod := jwt.GetSigningMethod(jwt.SigningMethodEdDSA.Alg())
	_, private, err := ed25519.GenerateKey(strings.NewReader(mnemonic))
	if err != nil {
		return nil, err
	}

	id := did + "#" + strings.ReplaceAll(did, "did:knox:", "")

	pk := &cryptosuite.PrivateKey{
		Id:            id,
		Controller:    did,
		CanonicalAlgo: urdna2015,
		SigningMethod: signingMethod,
		Type:          ed255192020,
		Key:           private,
	}

	doc := map[string]interface{}{}
	if err := json.Unmarshal([]byte(didDoc), &doc); err != nil {
		return nil, err
	}
	proofBuilder := dataintegrity.NewProofBuilder(pk, string(dataintegrity.ProofPurposeAssertionMethod))
	proof, err := proofBuilder.Source(doc).Build()
	if err != nil {
		return nil, err
	}

	return proof, nil
}
