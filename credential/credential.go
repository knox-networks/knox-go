package credential

import (
	"fmt"

	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	"github.com/knox-networks/knox-go/signer"
)

type CredentialClient interface {
	Request(params.RequestCredentialParams) (credential_adapter.VerifiableCredential, error)
}

type credentialClient struct {
	ca credential_adapter.CredentialAdapterClient
	s  signer.DynamicSigner
}

func NewCredentialClient(address string, s signer.DynamicSigner) (CredentialClient, error) {
	ca, err := credential_adapter.NewCredentialAdapterClient(address)
	if err != nil {
		return nil, err
	}
	return &credentialClient{ca: ca, s: s}, nil
}

func (c *credentialClient) Request(params params.RequestCredentialParams) (credential_adapter.VerifiableCredential, error) {
	did := c.s.GetDid()
	cred_type := params.CredentialType

	nonce, err := c.parseChallenge(params.Challenge, cred_type, did, params.AccessToken)
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}
	fmt.Println("Created issuance challenge")

	signature, err := c.s.Sign(signer.AssertionMethod, []byte(nonce))
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}
	fmt.Printf("Created Signature For Nonce %s\n", nonce)

	fmt.Printf("About to request issuance of credential of type %s\n", cred_type)
	cred, err := c.ca.IssueVerifiableCredential(cred_type, did, nonce, signature.ProofValue, params.AccessToken)
	if err != nil {
		return credential_adapter.VerifiableCredential{}, err
	}

	return cred, nil
}

func (c *credentialClient) parseChallenge(challenge params.RequestCredentialChallenge, credType string, did string, token string) (string, error) {
	if (challenge != params.RequestCredentialChallenge{}) {
		return challenge.Nonce, nil
	} else {
		challenge, err := c.ca.CreateIssuanceChallenge(credType, did, token)
		if err != nil {
			return "", err
		}
		return challenge.Nonce, nil
	}
}
