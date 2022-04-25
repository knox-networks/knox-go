package presentation

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Request(p params.RequestPresentationParams) error
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
	challenge, err := c.ca.CreatePresentationChallenge()
	if err != nil {
		return err
	}
	fmt.Printf("Challenge: %s, %s\n", challenge.Nonce, challenge.Url)
	convertedCreds := make([]map[string]interface{}, len(creds))

	for i, cred := range creds {
		var converted map[string]interface{}
		if err := json.Unmarshal(cred, &converted); err != nil {
			return err
		}

		convertedCreds[i] = converted
	}

	vp := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": convertedCreds,
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = model.NormalizationFormat
	options.Algorithm = model.NormalizationAlgo
	normalized, err := proc.Normalize(vp, options)

	if err != nil {
		return err
	}

	fmt.Printf("Normalized: %v\n", (normalized.(string)))

	proofValue, err := c.s.Sign(signer.AssertionMethod, []byte(normalized.(string)))
	if err != nil {
		return err
	}

	encoded, err := mb.Encode(mb.Base58BTC, proofValue)
	if err != nil {
		return err
	}

	err = c.ca.PresentVerifiableCredential(creds, model.Proof{
		Type:               model.ProofType,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: "",
		ProofPurpose:       signer.AssertionMethod.String(),
		ProofValue:         encoded,
	})
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

func (c *presentationClient) Request(p params.RequestPresentationParams) error {
	return errors.New("not implemented")
}
