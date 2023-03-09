package token

import (
	"errors"

	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/user_client"
	"github.com/knox-networks/knox-go/signer"
)

type tokenClient struct {
	auth user_client.UserClient
	s    signer.DynamicSigner
}
type TokenClient interface {
	Create(p *params.CreateTokenParams) (*model.AuthToken, error)
}

func NewTokenClient(address string, s signer.DynamicSigner) (TokenClient, error) {
	auth, err := user_client.NewAuthClient(address)
	if err != nil {
		return &tokenClient{}, err
	}
	return &tokenClient{auth: auth, s: s}, nil
}

func (c *tokenClient) Create(p *params.CreateTokenParams) (*model.AuthToken, error) {

	if p.Password != nil {

		token, err := c.auth.AuthenticateWithPassword(p.Password.Email, p.Password.Password)
		if err != nil {
			return nil, err
		}
		return token, nil
	} else if p.Did != nil {
		challenge, err := c.parseChallenge(p.Did.Challenge, p.Did.Did)
		if err != nil {
			return &model.AuthToken{}, err
		}

		signature, err := c.s.Sign(signer.Authentication, []byte(p.Did.Did+"."+challenge.Nonce))
		if err != nil {
			return &model.AuthToken{}, err
		}

		token, err := c.auth.AuthenticateWithDid(p.Did.Did, challenge.Nonce, signature.ProofValue)
		if err != nil {
			return &model.AuthToken{}, err
		}

		return token, nil
	} else {
		return &model.AuthToken{}, errors.New("no authentication method specified")
	}
}

func (c *tokenClient) parseChallenge(challenge *params.DidAuthenticationChallenge, did string) (*user_client.DidAuthenticationChallenge, error) {
	if challenge != nil {
		return &user_client.DidAuthenticationChallenge{}, nil
	} else {
		challenge, err := c.auth.CreateDidAuthenticationChallenge(did)
		if err != nil {
			return &user_client.DidAuthenticationChallenge{}, err
		}
		return challenge, nil
	}
}
