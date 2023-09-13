package dataintegrity

import (
	"time"
)

// https://w3c.github.io/vc-data-integrity/

// https://w3c-ccg.github.io/data-integrity-spec/#proofs
type Proof struct {
	Type               string    `json:"type"`
	ProofPurpose       string    `json:"proofPurpose"`
	VerificationMethod string    `json:"verificationMethod"`
	Created            time.Time `json:"created"`
	Domain             string    `json:"domain,omitempty"`
	ProofValue         string    `json:"proofValue"`
}

// https://w3c.github.io/vc-data-integrity/#proof-purposes
type ProofPurpose string

var (
	ProofPurposeAuthentication       ProofPurpose = "authentication"
	ProofPurposeAssertionMethod      ProofPurpose = "assertionMethod"
	ProofPurposeKeyAgreement         ProofPurpose = "keyAgreement"
	ProofPurposeCapabilityDelegation ProofPurpose = "capabilityDelegation"
	ProofPurposeCapabilityInvocation ProofPurpose = "capabilityInvocation"
)
