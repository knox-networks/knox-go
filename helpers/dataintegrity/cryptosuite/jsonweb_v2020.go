package cryptosuite

import "time"

type JsonWebKey2020 struct {
	Id           string      `json:"id"`
	Type         string      `json:"type"` // must be "JsonWebKey2020"
	Controller   string      `json:"controller"`
	PublicKeyJwk interface{} `json:"publicKeyJwk"`
}

type JSONWebSignature2020 struct {
	Type               string    `json:"type"` // must be "JsonWebSignature2020"
	VerificationMethod string    `json:"verificationMethod"`
	Created            time.Time `json:"created"`
	ProofPurpose       string    `json:"proofPurpose"`
	Jws                string    `json:"jws"`
}
