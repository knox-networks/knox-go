package cryptosuite

import "github.com/golang-jwt/jwt/v4"

type PublicKey struct {
	Id                   string
	Controller           string
	CanonicalAlgo        string
	SigningMethod        jwt.SigningMethod
	Type                 string
	Key                  interface{} //raw key format
	RequireCreated       bool
	ExpectedProofPurpose string
}

type PrivateKey struct {
	Id            string
	Controller    string
	CanonicalAlgo string
	SigningMethod jwt.SigningMethod
	Type          string
	Key           []byte //raw key format
}

type ProofPresentation struct {
	Method     interface{}
	PrivateKey PrivateKey
}

func (p *ProofPresentation) HasMatchVerificationMethod(vm interface{}) bool {
	switch vm.(type) {
	case Ed25519VerificationKey2020:
		if _, ok := p.Method.(Ed25519Signature2020); ok {
			return true
		}
	case JsonWebKey2020:
		if _, ok := p.Method.(JSONWebSignature2020); ok {
			return true
		}
	}
	return false
}
