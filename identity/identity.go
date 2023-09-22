package identity

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/knox-networks/knox-go/helpers/dataintegrity"
	"github.com/knox-networks/knox-go/helpers/dataintegrity/cryptosuite"
	"strings"

	"github.com/knox-networks/knox-go/helpers/crypto"
	"github.com/knox-networks/knox-go/helpers/did"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/registry_client"
	"github.com/knox-networks/knox-go/service/user_client"
	"github.com/knox-networks/knox-go/signer"
)

var (
	signingMethod    = jwt.GetSigningMethod(jwt.SigningMethodEdDSA.Alg())
	uRDNA2015        = "URDNA2015"
	ed25519Signature = "Ed25519Signature2020"
)

type identityClient struct {
	auth     user_client.UserClient
	s        signer.DynamicSigner
	cm       crypto.CryptoManager
	registry registry_client.RegistryClient
}

type IdentityClient interface {
	Register(p *params.RegisterIdentityParams) error
	Generate(params *params.GenerateIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error)
	Recover(p *params.RecoverIdentityParams) (*model.DidDocument, *crypto.KeyPairs, error)
	Revoke(p *params.RevocationIdentityParams) error
}

func NewIdentityClient(authAdress string, registryAddress string, s signer.DynamicSigner) (IdentityClient, error) {
	auth, err := user_client.NewAuthClient(authAdress)
	if err != nil {
		return nil, err
	}
	registry, err := registry_client.NewRegistryClient(registryAddress)
	if err != nil {
		return &identityClient{}, err
	}
	return &identityClient{auth: auth, s: s, cm: crypto.NewCryptoManager(), registry: registry}, nil
}

func (c *identityClient) Register(p *params.RegisterIdentityParams) error {
	did := c.s.GetDid()
	if p.Challenge != nil {
		nonce := p.Challenge.Nonce
		signed, err := c.s.Sign(signer.Authentication, []byte(did+"."+nonce))
		if err != nil {
			return err
		}

		if err := c.auth.AuthnWithDidRegister(did, nonce, signed.ProofValue); err != nil {
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

		if err := c.auth.AuthnWithDidRegister(did, nonce, signed.ProofValue); err != nil {
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

	if params.IssuerService != nil {
		issuerService := *params.IssuerService
		if !strings.HasPrefix(issuerService.Id, kps.GetDid()) {
			issuerService.Id = fmt.Sprintf("%s%s", kps.GetDid(), issuerService.Id)
		}
		doc.Service = append(doc.Service, issuerService)
	}

	encodedDoc, err := json.Marshal(doc)
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

	err = c.registry.Create(kps.GetDid(), encodedDoc)
	if err != nil {
		return &model.DidDocument{}, &crypto.KeyPairs{}, err
	}

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

func (c *identityClient) Revoke(p *params.RevocationIdentityParams) error {
	kps, err := c.cm.GenerateKeyPair(p.Mnemonic)
	if err != nil {
		return err
	}

	regDidDoc, err := c.registry.Resolve(p.Did)
	if err != nil {
		return err
	}

	didDocT, err := json.Marshal(regDidDoc)
	if err != nil {
		return err
	}

	didDoc := map[string]interface{}{}
	if err = json.Unmarshal(didDocT, &didDoc); err != nil {
		return err
	}

	pk := &cryptosuite.PrivateKey{
		Id:            kps.GetVerificationMethod(signer.AssertionMethod),
		Controller:    kps.GetDid(),
		CanonicalAlgo: uRDNA2015,
		SigningMethod: signingMethod,
		Type:          ed25519Signature,
		Key:           kps.GetPrivateKey(signer.AssertionMethod),
	}

	proofBuilder := dataintegrity.NewProofBuilder(pk, string(dataintegrity.ProofPurposeAssertionMethod))
	proof, err := proofBuilder.Source(didDoc).Build()
	if err != nil {
		return err
	}

	proofM, err := json.Marshal(proof)
	if err != nil {
		return err
	}

	proofValue := map[string]interface{}{}
	if err = json.Unmarshal(proofM, &proofValue); err != nil {
		return err
	}

	didDoc["proof"] = proofValue

	revocationDoc, err := json.Marshal(didDoc)
	if err != nil {
		return err
	}

	return c.registry.Revoke(p.Did, string(revocationDoc))
}
