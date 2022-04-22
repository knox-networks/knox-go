package knox

import (
	"github.com/knox-networks/knox-go/service/auth_client"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	"github.com/knox-networks/knox-go/signer"
)

const NormalizationAlgo = "URDNA2015"
const NormalizationFormat = "application/n-quads"
const ProofType = "Ed25519Signature2020"

type knoxClient struct {
	s    signer.DynamicSigner
	ca   credential_adapter.CredentialAdapterClient
	auth auth_client.AuthClient
}

type KnoxClient interface {
	RequestCredential(RequestCredentialParams) (credential_adapter.VerifiableCredential, error)
	SharePresentation(SharePresentationParams) error
	RequestPresentation(RequestPresentationParams) error
	RegisterIdentity(RegisterIdentityParams) error
	GenerateIdentity(GenerateIdentityParams) error
}

type KnoxConfig struct {
	Signer signer.DynamicSigner
	Issuer struct {
		CredentialAdapterURL string
		AuthServiceURL       string
	}
}

func NewKnoxClient(c KnoxConfig) (KnoxClient, error) {
	ca, err := credential_adapter.NewCredentialAdapterClient(c.Issuer.CredentialAdapterURL)
	if err != nil {
		return &knoxClient{}, err
	}
	auth, err := auth_client.NewAuthClient(c.Issuer.AuthServiceURL)
	if err != nil {
		return &knoxClient{}, err
	}
	return &knoxClient{s: c.Signer, ca: ca, auth: auth}, nil
}
