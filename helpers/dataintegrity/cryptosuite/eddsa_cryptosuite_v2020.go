package cryptosuite

import "time"

type Ed25519VerificationKey2020 struct {
	Id                 string `json:"id"`
	Type               string `json:"type"` // must be "Ed25519VerificationKey2020"
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type Ed25519Signature2020 struct {
	Id                 string    `json:"id"`
	Type               string    `json:"type"` // must be "Ed25519Signature2020"
	VerificationMethod string    `json:"verificationMethod"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	ProofValue         string    `json:"proofValue"`
}
