package identity

import (
	"errors"

	"github.com/knox-networks/knox-go/helpers/crypto"
	"github.com/knox-networks/knox-go/helpers/did"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/signer"
)

type identityClient struct {
	auth auth_client.AuthClient
	s    signer.DynamicSigner
	cm   crypto.CryptoManager
}

type IdentityClient interface {
	Register(p params.RegisterIdentityParams) error
	Generate(params params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error)
}

func NewIdentityClient(address string, s signer.DynamicSigner) (IdentityClient, error) {
	auth, err := auth_client.NewAuthClient(address)
	if err != nil {
		return &identityClient{}, err
	}
	return &identityClient{auth: auth, s: s, cm: crypto.NewCryptoManager()}, nil
}

func (c *identityClient) Register(params params.RegisterIdentityParams) error {
	return errors.New("not implemented")
}

func (c *identityClient) Generate(params params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	kps, err := c.cm.GenerateKeyPair()
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

	doc := did.CreateDidDocument(kps)

	return doc, kps, nil
}
