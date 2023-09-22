package signer

type VerificationRelation uint8

const (
	NotSupported VerificationRelation = iota
	Master
	Authentication
	CapabilityInvocation
	CapabilityDelegation
	AssertionMethod
	KeyAgreement
)

func (vr VerificationRelation) String() string {
	switch vr {
	case Master:
		return "master"
	case Authentication:
		return "authentication"
	case CapabilityInvocation:
		return "capabilityInvocation"
	case CapabilityDelegation:
		return "capabilityDelegation"
	case AssertionMethod:
		return "associationMethod"
	case KeyAgreement:
		return "keyAgreement"
	default:
		return ""
	}
}

type SigningResponse struct {
	ProofValue         []byte
	VerificationMethod string
	ProofType          string
}

type DynamicSigner interface {
	Sign(rel VerificationRelation, message []byte) (*SigningResponse, error)
	GetDid() string
}
