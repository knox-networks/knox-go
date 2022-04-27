package model

type SerializedDocument = []byte

type Proof struct {
	Type               string
	Created            string
	VerificationMethod string
	ProofPurpose       string
	ProofValue         string
}

const NormalizationAlgo = "URDNA2015"
const NormalizationFormat = "application/n-quads"
const ProofType = "Ed25519Signature2020"

const PermanentResidentCard = "PermanentResidentCard"
const BankCard = "BankCard"
