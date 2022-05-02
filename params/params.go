package params

import "github.com/knox-networks/knox-go/model"

type RequestCredentialChallenge struct {
	Nonce string
}

type RequestCredentialParams struct {
	CredentialType string
	Challenge      RequestCredentialChallenge
}

type SharePresentationParams struct {
	Credentials []model.SerializedDocument
}

type RequestPresentationParams struct {
	CredentialTypes []string
}

type RegisterIdentityChallenge struct {
	Nonce string
}

type RegisterIdentityParams struct {
	Challenge *RegisterIdentityChallenge
	Token     string
}

type GenerateIdentityParams struct {
}
