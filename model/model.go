package model

type SerializedDocument = interface{}

type Proof struct {
	Type               string
	Created            string
	VerificationMethod string
	ProofPurpose       string
	ProofValue         string
}

const NormalizationAlgo = "URDNA2015"
const NormalizationFormat = "application/n-quads"

// follow the algorithm here. (https://w3c-ccg.github.io/data-integrity-spec/#proof-algorithm)
const ProofType = "Ed25519Signature2020"

const (
	PermanentResidentCard = "PermanentResidentCard"
	BankCard              = "BankCard"
)

type KeyMaterial struct {
	Id                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}
type Service struct {
	Id              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type DidDocument struct {
	Context              []string      `json:"@context"`
	Id                   string        `json:"id"`
	Authentication       []KeyMaterial `json:"authentication"`
	Service              []Service     `json:"service,omitempty"`
	CapabilityInvocation []KeyMaterial `json:"capabilityInvocation"`
	CapabilityDelegation []KeyMaterial `json:"capabilityDelegation"`
	AssertionMethod      []KeyMaterial `json:"assertionMethod"`
	KeyAgreement         []KeyMaterial `json:"keyAgreement,omitempty"`
}

type AuthToken struct {
	Token        string
	TokenType    string
	ExpiresIn    int32
	RefreshToken string
}
