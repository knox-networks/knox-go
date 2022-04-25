package params

type RequestCredentialChallenge struct {
	Nonce string
}

type RequestCredentialParams struct {
	CredentialType string
	Challenge      RequestCredentialChallenge
}
