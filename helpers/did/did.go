package did

import "github.com/knox-networks/knox-go/helpers/crypto"

type KeyMaterial struct {
	Id                 string
	Typ                string
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
	return &DidDocument{}
}
