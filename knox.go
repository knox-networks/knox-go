package knox

import (
	"github.com/knox-networks/knox-go/credential"
	"github.com/knox-networks/knox-go/identity"
	"github.com/knox-networks/knox-go/presentation"
	"github.com/knox-networks/knox-go/signer"
	"github.com/knox-networks/knox-go/token"
)

type KnoxClient struct {
	s            signer.DynamicSigner
	Identity     identity.IdentityClient
	Credential   credential.CredentialClient
	Presentation presentation.PresentationClient
	Token        token.TokenClient
}

type NetworkConfig struct {
	CredentialAdapterURL string
	AuthServiceURL       string
	RegistryURL          string
}
type KnoxConfig struct {
	Signer  signer.DynamicSigner
	Network *NetworkConfig
}

func NewKnoxClient(c *KnoxConfig) (*KnoxClient, error) {
	client := &KnoxClient{}
	client.s = c.Signer
	if c.Network != nil {
		credClient, err := credential.NewCredentialClient(c.Network.CredentialAdapterURL, c.Signer)
		if err != nil {
			return &KnoxClient{}, err
		}
		presClient, err := presentation.NewPresentationClient(c.Network.CredentialAdapterURL, c.Signer)
		if err != nil {
			return &KnoxClient{}, err
		}

		identityClient, err := identity.NewIdentityClient(c.Network.AuthServiceURL, c.Network.RegistryURL, c.Signer)
		if err != nil {
			return &KnoxClient{}, err
		}

		tokenClient, err := token.NewTokenClient(c.Network.AuthServiceURL, c.Signer)
		if err != nil {
			return &KnoxClient{}, err
		}

		client.Credential = credClient
		client.Presentation = presClient
		client.Identity = identityClient
		client.Token = tokenClient
	}

	return client, nil
}

func (k *KnoxClient) UpdateConfig(c *KnoxConfig) error {

	if c.Signer != nil {
		k.s = c.Signer
	}

	if c.Network.CredentialAdapterURL != "" {

		credClient, err := credential.NewCredentialClient(c.Network.CredentialAdapterURL, c.Signer)
		if err != nil {
			return err
		}
		presClient, err := presentation.NewPresentationClient(c.Network.CredentialAdapterURL, c.Signer)
		if err != nil {
			return err
		}

		k.Credential = credClient
		k.Presentation = presClient
	}

	if c.Network.AuthServiceURL != "" {
		identityClient, err := identity.NewIdentityClient(c.Network.AuthServiceURL, c.Network.RegistryURL, c.Signer)
		if err != nil {
			return err
		}

		tokenClient, err := token.NewTokenClient(c.Network.AuthServiceURL, c.Signer)
		if err != nil {
			return err
		}

		k.Identity = identityClient
		k.Token = tokenClient

	}
	return nil
}
