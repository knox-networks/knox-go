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

const (
	PermanentResidentCard = "PermanentResidentCard"
	BankCard              = "BankCard"
)

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

type AuthToken struct {
	Token        string
	TokenType    string
	ExpiresIn    int32
	RefreshToken string
}
