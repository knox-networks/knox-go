package params

import "github.com/knox-networks/knox-go/model"

type RequestCredentialChallenge struct {
	Nonce string
}

type RequestCredentialParams struct {
	CredentialType string
	Challenge      RequestCredentialChallenge
	AccessToken    string
}

type SharePresentationChallenge struct {
	Nonce           string
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
	IssuerService *model.Service
}

type RecoverIdentityParams struct {
	Mnemonic string
}

type RevocationIdentityParams struct {
	Mnemonic string
	Did      string
}

type PasswordAuthentication struct {
	Password string
	Email    string
}

type DidAuthenticationChallenge struct {
	Nonce string
}

type DidAuthentication struct {
	Did       string
	Challenge *DidAuthenticationChallenge
}
type CreateTokenParams struct {
	Password *PasswordAuthentication
	Did      *DidAuthentication
}
