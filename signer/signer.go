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

type DynamicSigner interface {
	Sign(rel VerificationRelation, message []byte) ([]byte, error)
	GetDid() string
}
