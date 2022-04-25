package knox

import (
	"github.com/knox-networks/knox-go/credential"
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	"github.com/knox-networks/knox-go/signer"
)

const NormalizationAlgo = "URDNA2015"
const NormalizationFormat = "application/n-quads"
const ProofType = "Ed25519Signature2020"

type KnoxClient struct {
	s          signer.DynamicSigner
	ca         credential_adapter.CredentialAdapterClient
	auth       auth_client.AuthClient
	Credential credential.CredentialClient
}

type KnoxConfig struct {
	Signer signer.DynamicSigner
	Issuer struct {
		CredentialAdapterURL string
		AuthServiceURL       string
	}
}

func NewKnoxClient(c KnoxConfig) (*KnoxClient, error) {
	credClient, err := credential.NewCredentialClient(c.Issuer.CredentialAdapterURL, c.Signer)
	if err != nil {
		return &KnoxClient{}, err
	}
	auth, err := auth_client.NewAuthClient(c.Issuer.AuthServiceURL)
	if err != nil {
		return &KnoxClient{}, err
	}
	return &KnoxClient{s: c.Signer, auth: auth, Credential: credClient}, nil
}
