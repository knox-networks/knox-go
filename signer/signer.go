package signer

type DynamicSigner interface {
	Sign(message []byte) ([]byte, error)
	GetDid() string
}
