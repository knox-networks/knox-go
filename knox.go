package knox

import (
	"github.com/knox-networks/knox-go/credential_adapter"
)

const NormalizationAlgo = "URDNA2015"
const NormalizationFormat = "application/n-quads"
const ProofType = "Ed25519Signature2020"

type DynamicSigner interface {
	Sign(message []byte) ([]byte, error)
	GetDid() string
}

type knoxClient struct {
	signer DynamicSigner
	ca     credential_adapter.CredentialAdapterClient
}

type KnoxClient interface {
	RequestCredential(RequestCredentialParams) (credential_adapter.VerifiableCredential, error)
	SharePresentation(SharePresentationParams) error
	RequestPresentation(RequestPresentationParams) error
	RegisterIdentity(RegisterIdentityParams) error
	GenerateIdentity(GenerateIdentityParams) error
}

func NewKnoxClient(wallet DynamicSigner) (KnoxClient, error) {
	ca, err := credential_adapter.NewCredentialAdapterClient()
	if err != nil {
		return &knoxClient{}, err
	}
	return &knoxClient{signer: wallet, ca: ca}, nil
}
