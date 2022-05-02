package identity

import (
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

func (c *identityClient) Register(p params.RegisterIdentityParams) error {

	nonce, err := c.parseChallenge(p.Challenge, p.Token)
	if err != nil {
		return err
	}
	did := c.s.GetDid()
	signed, err := c.s.Sign(signer.Authentication, []byte(did+"."+nonce))
	if err != nil {
		return err
	}

	err = c.auth.AuthnWithDidRegister(did, nonce, signed)
	if err != nil {
		return err
	}
	return nil
}

func (c *identityClient) parseChallenge(challenge *params.RegisterIdentityChallenge, token string) (string, error) {
	if challenge != nil {
		return challenge.Nonce, nil
	} else {
		challenge, err := c.auth.CreateDidRegistrationChallenge(token)
		if err != nil {
			return "", err
		}
		return challenge.Nonce, nil
	}
}

func (c *identityClient) Generate(params params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	kps, err := c.cm.GenerateKeyPair()
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

	doc := did.CreateDidDocument(kps)

	return doc, kps, nil
}
