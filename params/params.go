package params

import "github.com/knox-networks/knox-go/model"

type RequestCredentialChallenge struct {
	Nonce string
}

type RequestCredentialParams struct {
	CredentialType string
	Challenge      RequestCredentialChallenge
}

type SharePresentationChallenge struct {
	Nonce           string
	Url             string
	CredentialTypes []string
}
type SharePresentationParams struct {
	Credentials     []model.SerializedDocument
	CredentialTypes []string
	Challenge       SharePresentationChallenge
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

type PasswordAuthentication struct {
	Password string
	Email    string
}

type DidAuthentication struct {
	Did string
}
type CreateTokenParams struct {
	Password *PasswordAuthentication
	Did      *DidAuthentication
}
