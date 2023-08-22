package did

import (
	"github.com/knox-networks/knox-go/helpers/crypto"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/signer"
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
