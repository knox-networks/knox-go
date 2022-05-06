package presentation

import (
	"time"

	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	"github.com/knox-networks/knox-go/signer"
	mb "github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

type presentationClient struct {
	ca credential_adapter.CredentialAdapterClient
	s  signer.DynamicSigner
}

type PresentationClient interface {
	Share(p params.SharePresentationParams) error
	Request(p params.RequestPresentationParams) (*credential_adapter.PresentationChallenge, error)
}

func NewPresentationClient(address string, s signer.DynamicSigner) (PresentationClient, error) {
	ca, err := credential_adapter.NewCredentialAdapterClient(address)
	if err != nil {
		return nil, err
	}
	return &presentationClient{ca: ca, s: s}, nil
}

func (c *presentationClient) Share(p params.SharePresentationParams) error {
	creds := p.Credentials

	vp := map[string]interface{}{
		"@context":             []interface{}{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		"type":                 []interface{}{"VerifiablePresentation"},
		"verifiableCredential": creds,
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = model.NormalizationFormat
	options.Algorithm = model.NormalizationAlgo
	normalized, err := proc.Normalize(vp, options)

	if err != nil {
		return err
	}

	proofValue, err := c.s.Sign(signer.AssertionMethod, []byte(normalized.(string)))
	if err != nil {
		return err
	}

	encoded, err := mb.Encode(mb.Base58BTC, proofValue.Signature)
	if err != nil {
		return err
	}

	signature, err := c.s.Sign(signer.AssertionMethod, []byte(p.Challenge.Nonce))

	if err != nil {
		return err
	}

	err = c.ca.PresentVerifiableCredential(creds, model.Proof{
		Type:               model.ProofType,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: "PLACEHOLDER",
		ProofPurpose:       signer.AssertionMethod.String(),
		ProofValue:         encoded,
	}, c.s.GetDid(), p.Challenge.Nonce, signature.Signature)

	if err != nil {
		return err
	}

	return nil
}

func (c *presentationClient) Request(p params.RequestPresentationParams) (*credential_adapter.PresentationChallenge, error) {
	challenge, err := c.ca.CreatePresentationChallenge(p.CredentialTypes)
	if err != nil {
		return &credential_adapter.PresentationChallenge{}, err
	}

	return challenge, nil
}
