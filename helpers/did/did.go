package did

import (
	"github.com/knox-networks/knox-go/helpers/crypto"
	"github.com/knox-networks/knox-go/model"
)

func CreateDidDocument(kps *crypto.KeyPairs) *model.DidDocument {
	return &model.DidDocument{
		Context: []string{"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1"},
		Id: kps.MasterPublicKey,
		Authentication: []model.KeyMaterial{
			{
				Id:                 crypto.DidPrefix + kps.MasterPublicKey + "#" + kps.AuthenticationPublicKey,
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AuthenticationPublicKey,
			},
		},
		CapabilityInvocation: []model.KeyMaterial{
			{
				Id:                 crypto.DidPrefix + kps.MasterPublicKey + "#" + kps.CapabilityInvocationPublicKey,
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityInvocationPublicKey,
			},
		},
		CapabilityDelegation: []model.KeyMaterial{
			{
				Id:                 crypto.DidPrefix + kps.MasterPublicKey + "#" + kps.CapabilityDelegationPublicKey,
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityDelegationPublicKey,
			},
		},
		AssertionMethod: []model.KeyMaterial{
			{
				Id:                 crypto.DidPrefix + kps.MasterPublicKey + "#" + kps.AssertionMethodPublicKey,
				Type:               crypto.ProofType,
				Controller:         crypto.DidPrefix + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AssertionMethodPublicKey,
			},
		},
	}
}
