package signer

type VerificationRelation uint8

const (
	NotSupported VerificationRelation = iota
	Master
	Authentication
	CapabilityInvocation
	CapabilityDelegation
	AssertionMethod
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
	default:
		return ""
	}
}

type DynamicSigner interface {
	Sign(rel VerificationRelation, message []byte) ([]byte, error)
	GetDid() string
}
