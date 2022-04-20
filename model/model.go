package model

type SerializedDocument = []byte

type Proof struct {
	Type               string
	Created            string
	VerificationMethod string
	ProofPurpose       string
	ProofValue         string
}

type VerifiableCredential struct {
	Context      []string          `json:"@context"`
	Id           string            `json:"id,omitempty"`
	Type         []string          `json:"type"`
	Issuer       string            `json:"issuer"`
	IssuanceDate string            `json:"issuanceDate"`
	Subject      CredentialSubject `json:"credentialSubject"`
	Proof        *Proof            `json:"proof"`
}

type VerifiablePresentation struct {
	Context              []string               `json:"@context"`
	Id                   string                 `json:"id,omitempty"`
	Type                 []string               `json:"type"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
	Proof                *Proof                 `json:"proof,omitempty"`
}

type CredentialSubject = map[string]interface{}
