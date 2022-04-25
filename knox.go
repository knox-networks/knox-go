package knox

import (
	"github.com/knox-networks/knox-go/credential"
	"github.com/knox-networks/knox-go/identity"
	"github.com/knox-networks/knox-go/presentation"
	"github.com/knox-networks/knox-go/signer"
)

type KnoxClient struct {
	s            signer.DynamicSigner
	Identity     identity.IdentityClient
	Credential   credential.CredentialClient
	Presentation presentation.PresentationClient
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
	presClient, err := presentation.NewPresentationClient(c.Issuer.CredentialAdapterURL, c.Signer)
	if err != nil {
		return &KnoxClient{}, err
	}

	identityClient, err := identity.NewIdentityClient(c.Issuer.AuthServiceURL, c.Signer)
	if err != nil {
		return &KnoxClient{}, err
	}

	return &KnoxClient{s: c.Signer,
		Credential:   credClient,
		Presentation: presClient,
		Identity:     identityClient,
	}, nil
}

func (k *KnoxClient) UpdateConfig(c *KnoxConfig) error {

	if c.Signer != nil {
		k.s = c.Signer
	}

	if c.Issuer.CredentialAdapterURL != "" {

		credClient, err := credential.NewCredentialClient(c.Issuer.CredentialAdapterURL, c.Signer)
		if err != nil {
			return err
		}
		presClient, err := presentation.NewPresentationClient(c.Issuer.CredentialAdapterURL, c.Signer)
		if err != nil {
			return err
		}

		k.Credential = credClient
		k.Presentation = presClient
	}

	if c.Issuer.AuthServiceURL != "" {
		identityClient, err := identity.NewIdentityClient(c.Issuer.AuthServiceURL, c.Signer)
		if err != nil {
			return err
		}

		k.Identity = identityClient

	}
	return nil
}
