package token

import (
	"errors"

	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/signer"
)

type tokenClient struct {
	auth auth_client.AuthClient
	s    signer.DynamicSigner
}
type TokenClient interface {
	Create(p *params.CreateTokenParams) (string, error)
}

func NewTokenClient(address string, s signer.DynamicSigner) (TokenClient, error) {
	auth, err := auth_client.NewAuthClient(address)
	if err != nil {
		return &tokenClient{}, err
	}
	return &tokenClient{auth: auth, s: s}, nil
}

func (c *tokenClient) Create(p *params.CreateTokenParams) (string, error) {

	if p.Password != nil {
		return "", errors.New("password authentication not supported")
	} else if p.Did != nil {
		challenge, streamClient, err := c.auth.CreateDidAuthenticationChallenge()
		if err != nil {
			return "", err
		}

		signature, err := c.s.Sign(signer.Authentication, []byte(p.Did.Did+"."+challenge.Nonce))
		if err != nil {
			return "", err
		}

		if err := c.auth.AuthnWithDid(p.Did.Did, challenge.Nonce, signature); err != nil {
			return "", err
		}

		err = streamClient.WaitForCompletion()

		if err != nil {
			return "", err
		}

		return "", errors.New("did authentication not supported")
	} else {
		return "", errors.New("no authentication method specified")
	}
}
