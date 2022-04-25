package identity

import (
	"errors"

	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/signer"
)

type identityClient struct {
	auth auth_client.AuthClient
	s    signer.DynamicSigner
}

type IdentityClient interface {
	RegisterIdentity(p params.RegisterIdentityParams) error
	GenerateIdentity(params params.GenerateIdentityParams) error
}

func NewIdentityClient(address string, s signer.DynamicSigner) (IdentityClient, error) {
	auth, err := auth_client.NewAuthClient(address)
	if err != nil {
		return &identityClient{}, err
	}
	return &identityClient{auth: auth, s: s}, nil
}

func (c *identityClient) RegisterIdentity(params params.RegisterIdentityParams) error {
	return errors.New("not implemented")
}

func (c *identityClient) GenerateIdentity(params params.GenerateIdentityParams) error {
	return errors.New("not implemented")
}
