package knox

import (
	"testing"

	"github.com/golang/mock/gomock"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

func TestNewKnoxClient(t *testing.T) {
	mock_controller := gomock.NewController(t)
	mock_signer := s_mock.NewMockDynamicSigner(mock_controller)

	_, err := NewKnoxClient(&KnoxConfig{
		Signer: mock_signer,
		Network: &NetworkConfig{
			CredentialAdapterURL: "",
			AuthServiceURL:       "",
		},
	})

	if err != nil {
		t.Errorf("Error creating knox client: %s", err)
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

	c.UpdateConfig(&KnoxConfig{
		Network: &NetworkConfig{
			CredentialAdapterURL: "vc.knoxnetworks.io:5051",
			AuthServiceURL:       "auth.knoxnetworks.io:5051",
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
