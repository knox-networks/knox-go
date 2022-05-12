package token

import (
	"errors"

	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/signer"
	AuthApi "go.buf.build/grpc/go/knox-networks/auth-mgmt/auth_api/v1"
)

type tokenClient struct {
	auth auth_client.AuthClient
	s    signer.DynamicSigner
}
type TokenClient interface {
	Create(p *params.CreateTokenParams) (*model.AuthToken, error)
}

func NewTokenClient(address string, s signer.DynamicSigner) (TokenClient, error) {
	auth, err := auth_client.NewAuthClient(address)
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
		challenge, streamClient, err := c.parseChallenge(p.Did.Challenge)
		if err != nil {
			return &model.AuthToken{}, err
		}

		signature, err := c.s.Sign(signer.Authentication, []byte(p.Did.Did+"."+challenge.Nonce))
		if err != nil {
			return &model.AuthToken{}, err
		}

		if err := c.auth.AuthnWithDid(p.Did.Did, challenge.Nonce, signature.ProofValue); err != nil {
			return &model.AuthToken{}, err
		}

		if streamClient != nil {
			message, err := streamClient.Recv()

			if err != nil {
				return &model.AuthToken{}, err
			}

			token := message.GetAuthToken().AuthToken

			if err := streamClient.CloseSend(); err != nil {
				return &model.AuthToken{}, err
			}

			return &model.AuthToken{
				Token:        token.Token,
				TokenType:    token.TokenType,
				RefreshToken: token.RefreshToken,
				ExpiresIn:    token.ExpiresIn,
			}, nil
		} else {
			return &model.AuthToken{}, nil
		}
	} else {
		return &model.AuthToken{}, errors.New("no authentication method specified")
	}
}

func (c *tokenClient) parseChallenge(challenge *params.DidAuthenticationChallenge) (*auth_client.DidAuthenticationChallenge, AuthApi.AuthApiService_AuthnWithDidStartClient, error) {
	if challenge != nil {
		return &auth_client.DidAuthenticationChallenge{}, nil, nil
	} else {
		challenge, streamClient, err := c.auth.CreateDidAuthenticationChallenge()
		if err != nil {
			return &auth_client.DidAuthenticationChallenge{}, nil, err
		}
		return challenge, streamClient, nil
	}
}
