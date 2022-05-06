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
	Register(p *params.RegisterIdentityParams) error
	Generate(params *params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error)
	Recover(p *params.RecoverIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error)
}

func NewIdentityClient(address string, s signer.DynamicSigner) (IdentityClient, error) {
	auth, err := auth_client.NewAuthClient(address)
	if err != nil {
		return &identityClient{}, err
	}
	return &identityClient{auth: auth, s: s, cm: crypto.NewCryptoManager()}, nil
}

func (c *identityClient) Register(p *params.RegisterIdentityParams) error {
	did := c.s.GetDid()
	if p.Challenge != nil {
		nonce := p.Challenge.Nonce
		signed, err := c.s.Sign(signer.Authentication, []byte(did+"."+nonce))
		if err != nil {
			return err
		}

		if err := c.auth.AuthnWithDidRegister(did, nonce, signed.Signature); err != nil {
			return err
		}

	} else {
		challenge, stream, err := c.auth.CreateDidRegistrationChallenge(p.Token)
		if err != nil {
			return err
		}
		nonce := challenge.Nonce
		signed, err := c.s.Sign(signer.Authentication, []byte(did+"."+nonce))
		if err != nil {
			return err
		}

		if err := c.auth.AuthnWithDidRegister(did, nonce, signed.Signature); err != nil {
			return err
		}

		if err := stream.WaitForCompletion(); err != nil {
			return err
		}

		if err := stream.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (c *identityClient) Generate(params *params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	mnemonic, err := c.cm.GenerateMnemonic()
	if err != nil {
		return nil, nil, err
	}
	kps, err := c.cm.GenerateKeyPair(mnemonic)
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

	doc := did.CreateDidDocument(kps)

	return doc, kps, nil
}

func (c *identityClient) Recover(p *params.RecoverIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error) {
	kps, err := c.cm.GenerateKeyPair(p.Mnemonic)
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

	doc := did.CreateDidDocument(kps)

	return doc, kps, nil
}
