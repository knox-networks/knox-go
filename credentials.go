package knox

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/knox-networks/knox-go/credential_adapter"
	"github.com/knox-networks/knox-go/model"
	mb "github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

type RequestCredentialParams struct {
	CredentialType string
}

type SharePresentationParams struct {
	Credentials []model.SerializedDocument
}

type RequestPresentationParams struct {
}

func (c *knoxClient) RequestCredential(params RequestCredentialParams) (credential_adapter.VerifiableCredential, error) {
	did := c.s.GetDid()
	cred_type := params.CredentialType
	qrCode, err := c.ca.CreateIssuanceChallenge(cred_type, did)
	fmt.Println("Created issuance challenge")
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}
	signature, err := c.s.Sign([]byte(qrCode.Nonce))
	fmt.Printf("Created Signature For Nonce %s\n", qrCode.Nonce)
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}

	fmt.Printf("About to request issuance of credential of type %s\n", cred_type)
	cred, err := c.ca.IssueVerifiableCredential(cred_type, did, qrCode.Nonce, signature)
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}

	return cred, nil
}

func (c *knoxClient) SharePresentation(params SharePresentationParams) error {
	creds := params.Credentials
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
	options.Format = NormalizationFormat
	options.Algorithm = NormalizationAlgo
	normalized, err := proc.Normalize(vp, options)

	if err != nil {
		return err
	}

	fmt.Printf("Normalized: %v\n", (normalized.(string)))

	proofValue, err := c.s.Sign([]byte(normalized.(string)))
	if err != nil {
		return err
	}

	encoded, err := mb.Encode(mb.Base58BTC, proofValue)
	if err != nil {
		return err
	}

	err = c.ca.PresentVerifiableCredential(creds, model.Proof{
		Type:               ProofType,
		Created:            time.Now().UTC().Format(time.RFC3339),
		VerificationMethod: "",
		ProofPurpose:       "assertionMethod",
		ProofValue:         encoded,
	})
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

func (c *knoxClient) RequestPresentation(params RequestPresentationParams) error {
	return errors.New("not implemented")
}
