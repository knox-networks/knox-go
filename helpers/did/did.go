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
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.AuthenticationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AuthenticationPublicKey,
			},
		},
		CapabilityInvocation: []model.KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.CapabilityInvocationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityInvocationPublicKey,
			},
		},
		CapabilityDelegation: []model.KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.CapabilityDelegationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityDelegationPublicKey,
			},
		},
		AssertionMethod: []model.KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.AssertionMethodPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AssertionMethodPublicKey,
			},
		},
	}
}
