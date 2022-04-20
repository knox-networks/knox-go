package model

type SerializedDocument = []byte

type Proof struct {
	Type               string
	Created            string
	VerificationMethod string
	ProofPurpose       string
	ProofValue         string
}
