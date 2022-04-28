package did

import "github.com/knox-networks/knox-go/helpers/crypto"

type KeyMaterial struct {
	Id                 string
	Type               string
	Controller         string
	PublicKeyMultibase string
}

type DidDocument struct {
	Context              []string      `json:"@context"`
	Id                   string        `json:"id"`
	Authentication       []KeyMaterial `json:"authentication"`
	CapabilityInvocation []KeyMaterial `json:"capabilityInvocation"`
	CapabilityDelegation []KeyMaterial `json:"capabilityDelegation"`
	AssertionMethod      []KeyMaterial `json:"assertionMethod"`
}

func CreateDidDocument(kps *crypto.KeyPairs) *DidDocument {
	return &DidDocument{
		Context: []string{"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1"},
		Id: kps.MasterPublicKey,
		Authentication: []KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.AuthenticationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AuthenticationPublicKey,
			},
		},
		CapabilityInvocation: []KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.CapabilityInvocationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityInvocationPublicKey,
			},
		},
		CapabilityDelegation: []KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.CapabilityDelegationPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.CapabilityDelegationPublicKey,
			},
		},
		AssertionMethod: []KeyMaterial{
			{
				Id:                 crypto.DID_PREFIX + kps.MasterPublicKey + "#" + kps.AssertionMethodPublicKey,
				Type:               crypto.PROOF_TYPE,
				Controller:         crypto.DID_PREFIX + kps.MasterPublicKey,
				PublicKeyMultibase: kps.AssertionMethodPublicKey,
			},
		},
	}
}
