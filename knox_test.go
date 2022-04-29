package knox

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/params"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

func TestNewKnoxClient(t *testing.T) {
	mock_controller := gomock.NewController(t)
	mock_signer := s_mock.NewMockDynamicSigner(mock_controller)

	c, err := NewKnoxClient(&KnoxConfig{
		Signer: mock_signer,
		Network: &NetworkConfig{
			CredentialAdapterURL: "",
			AuthServiceURL:       "",
		},
	})

	if err != nil {
		t.Errorf("Error creating knox client: %s", err)
	}

	if (c.Credential == nil) || (c.Presentation == nil) || (c.Identity == nil) {
		t.Errorf("Knox client is missing one or more of the required clients")
	}

}

func TestUpdateConfig(t *testing.T) {
	mock_controller := gomock.NewController(t)
	mock_signer := s_mock.NewMockDynamicSigner(mock_controller)

	c, err := NewKnoxClient(&KnoxConfig{
		Signer: mock_signer,
		Network: &NetworkConfig{
			CredentialAdapterURL: "",
			AuthServiceURL:       "",
		},
	})

	if err != nil {
		t.Errorf("Error creating knox client: %s", err)
	}

	cred := c.Credential
	identity := c.Identity
	pres := c.Presentation

	_, kps, _ := c.Identity.Generate(params.GenerateIdentityParams{})

	c.UpdateConfig(&KnoxConfig{
		Signer: kps,
		Network: &NetworkConfig{
			CredentialAdapterURL: "localhost:5051",
			AuthServiceURL:       "localhost:5052",
		},
	})

	if cred == c.Credential {
		t.Errorf("Credential client not updated")
	}

	if pres == c.Presentation {
		t.Errorf("Presentation client not updated")
	}

	if identity == c.Identity {
		t.Errorf("Identity client not updated")
	}

}
