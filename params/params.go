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
}

type RegisterIdentityParams struct {
}

type GenerateIdentityParams struct {
}
