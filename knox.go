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

const NORMALIZATION_ALGO = "URDNA2015"
const NORMALIZATION_FORMAT = "application/n-quads"
const PROOF_TYPE = "Ed25519Signature2020"

type Wallet interface {
	Sign(message []byte) ([]byte, error)
	GetDid() string
}

type knoxClient struct {
	wallet Wallet
	ca     credential_adapter.CredentialAdapterClient
}

type KnoxClient interface {
	RequestCredential(cred_type string) (credential_adapter.VerifiableCredential, error)
	PresentCredential(cred ...model.SerializedDocument) error
}

func NewKnoxClient(wallet Wallet) (KnoxClient, error) {
	ca, err := credential_adapter.NewCredentialAdapterClient()
	if err != nil {
		return &knoxClient{}, err
	}
	return &knoxClient{wallet: wallet, ca: ca}, nil
}

func (c *knoxClient) RequestCredential(cred_type string) (credential_adapter.VerifiableCredential, error) {
	did := c.wallet.GetDid()
	qrCode, err := c.ca.CreateIssuanceChallenge(cred_type, did)
	fmt.Println("Created issuance challenge")
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}
	signature, err := c.wallet.Sign([]byte(qrCode.Nonce))
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

func (c *knoxClient) PresentCredential(creds ...model.SerializedDocument) error {

	challenge, err := c.ca.CreatePresentationChallenge()
	if err != nil {
		return err
	}
	fmt.Printf("Challenge: %s, %s\n", challenge.Nonce, challenge.Url)
	converted_creds := make([]map[string]interface{}, len(creds))

	for i, cred := range creds {
		var converted_cred map[string]interface{}
		err = json.Unmarshal(cred, &converted_cred)

		if err != nil {
			return err
		}

		converted_creds[i] = converted_cred
	}

	vp := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": converted_creds,
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = NORMALIZATION_FORMAT
	options.Algorithm = NORMALIZATION_ALGO
	normalized, err := proc.Normalize(vp, options)

	if err != nil {
		fmt.Printf("Error normalizing: %s\n", err.Error())
		return err
	}

	fmt.Printf("Normalized: %v\n", (normalized.(string)))

	proofValue, err := c.wallet.Sign([]byte(normalized.(string)))
	if err != nil {
		return err
	}

	encoded, err := mb.Encode(mb.Base58BTC, proofValue)
	if err != nil {
		return err
	}

	err = c.ca.PresentVerifiableCredential(creds, model.Proof{
		Type:               PROOF_TYPE,
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
