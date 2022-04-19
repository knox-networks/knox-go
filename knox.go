package knox

import (
	"errors"
	"fmt"

	"github.com/knox-networks/knox-go/credential_adapter"
)

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
	PresentCredential(cred credential_adapter.VerifiableCredential) error
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

func (c *knoxClient) PresentCredential(cred credential_adapter.VerifiableCredential) error {

	challenge, err := c.ca.CreatePresentationChallenge(cred.Type)
	if err != nil {
		return err
	}

	fmt.Printf("Challenge: %s, %s, %s", challenge.Nonce, challenge.Url, challenge.CredType)
	err = c.ca.PresentVerifiableCredential(cred)
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}
