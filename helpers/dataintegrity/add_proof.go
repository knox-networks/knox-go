package dataintegrity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"github.com/knox-networks/knox-go/helpers/dataintegrity/cryptosuite"

	"errors"

	"time"
)

// ProofBuilder https://w3c.github.io/vc-data-integrity/#add-proof
type ProofBuilder struct {
	privateKey *cryptosuite.PrivateKey
	src        interface{}
	purpose    string
}

func NewProofBuilder(pk *cryptosuite.PrivateKey, purpose string) *ProofBuilder {
	return &ProofBuilder{
		privateKey: pk,
		purpose:    purpose,
	}
}

func (p *ProofBuilder) Source(src interface{}) *ProofBuilder {
	p.src = src
	return p
}

// https://w3c.github.io/vc-data-integrity/#add-proof
func (p *ProofBuilder) Build() (*Proof, error) {
	if p.src == nil {
		return nil, errors.New("source can't be nil")
	}

	//1. normalize the source document
	ns, err := Normalize(p.src, p.privateKey.CanonicalAlgo)
	if err != nil {
		return nil, err
	}

	//2. digest normalized source
	ks := sha256.New()
	ks.Write([]byte(*ns))
	digest := ks.Sum(nil)

	//3. sign with private key
	privK := ed25519.PrivateKey(p.privateKey.Key)
	signed, err := p.privateKey.SigningMethod.Sign(string(digest), privK)
	if err != nil {
		return nil, err
	}

	return &Proof{
		Type:               p.privateKey.Type,
		Created:            time.Now(),
		ProofPurpose:       p.purpose,
		VerificationMethod: p.privateKey.Id,
		ProofValue:         signed,
	}, nil
}
