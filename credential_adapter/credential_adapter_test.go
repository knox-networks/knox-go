package credential_adapter

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	mock_client "github.com/knox-networks/knox-go/credential_adapter/grpc_mock"
	AdapterApi "go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1"
)

type createIssuanceQrCodeTest struct {
	mockNonce              string
	mockClientRequestError error
	expectedChallenge      IssuanceChallenge
	expectedError          error
}

func TestCreateIssuanceChallenge(t *testing.T) {
	did := "did:knox:test"
	cred_type := "test"
	nonce := "rbmtI32kWmVpdv22i4QDEYtFwjIP22W7"
	url := "vc.knoxnetworks.io:5051"
	mock_controller := gomock.NewController(t)

	tests := []createIssuanceQrCodeTest{
		{
			mockNonce:              nonce,
			mockClientRequestError: nil,
			expectedChallenge: IssuanceChallenge{
				Nonce:    nonce,
				CredType: cred_type,
				Url:      url,
			},
			expectedError: nil,
		},
		{
			mockNonce:              nonce,
			mockClientRequestError: errors.New("error"),
			expectedChallenge:      IssuanceChallenge{},
			expectedError:          errors.New("error"),
		},
	}

	for _, test := range tests {
		client := mock_client.NewMockAdapterServiceClient(mock_controller)
		adapter_client := &credentialAdapterClient{
			client: client,
		}

		client.EXPECT().
			CreateIssuanceChallenge(gomock.Any(), &AdapterApi.CreateIssuanceChallengeRequest{
				CredentialType: getCredentialEnumFromName(cred_type),
				Did:            did,
			}).
			Return(&AdapterApi.CreateIssuanceChallengeResponse{
				Nonce:          test.mockNonce,
				CredentialType: getCredentialEnumFromName(cred_type),
				Endpoint:       CREDENTIAL_ADAPTER_ADDRESS,
			}, test.mockClientRequestError)

		challenge, err := adapter_client.CreateIssuanceChallenge(cred_type, did)

		if err != nil && test.expectedError == nil || err == nil && test.expectedError != nil {
			t.Errorf("Expected error %v, but got %v", test.expectedError, err)
		}

		if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
			t.Errorf("Expected error %v, but got %v", test.expectedError, err)
		}

		if challenge.Nonce != test.expectedChallenge.Nonce {
			t.Errorf("Expected nonce %v, but got %v", test.expectedChallenge.Nonce, challenge.Nonce)
		}

		if challenge.Url != test.expectedChallenge.Url {
			t.Errorf("Expected url %v, but got %v", test.expectedChallenge.Url, challenge.Url)
		}

		if challenge.CredType != test.expectedChallenge.CredType {
			t.Errorf("Expected cred_type %v, but got %v", test.expectedChallenge.CredType, challenge.CredType)
		}

	}

}

type createPresentationChallengeTest struct{}

func TestCreatePresentationChallenge(t *testing.T) {
	t.Skip("Not implemented")
}

type IssueVerifiableCredentialTest struct {
	mockClientRequestError error
	expectedError          error
	expectedCredType       string
}

func TestIssueVerifiableCredential(t *testing.T) {
	did := "did:knox:test"
	cred_type := "test"
	nonce := "rbmtI32kWmVpdv22i4QDEYtFwjIP22W7"
	signature := []byte("signature")
	cred_id := "123456"
	mock_controller := gomock.NewController(t)

	tests := []IssueVerifiableCredentialTest{
		{
			mockClientRequestError: nil,
			expectedError:          nil,
			expectedCredType:       cred_type,
		},
		{
			mockClientRequestError: errors.New("request error"),
			expectedError:          errors.New("request error"),
			expectedCredType:       "",
		},
	}
	client := mock_client.NewMockAdapterServiceClient(mock_controller)

	for _, test := range tests {

		adapter_client := &credentialAdapterClient{
			client: client,
		}
		client.EXPECT().IssueVerifiableCredential(gomock.Any(), &AdapterApi.IssueVerifiableCredentialRequest{
			CredentialType: getCredentialEnumFromName(cred_type),
			Did:            did,
			Nonce:          nonce,
			Signature:      signature,
		}).Return(&AdapterApi.IssueVerifiableCredentialResponse{Credential: &AdapterApi.VerifiableCredential{Id: cred_id}}, test.mockClientRequestError)

		cred, err := adapter_client.IssueVerifiableCredential(cred_type, did, nonce, signature)

		if err != nil && test.expectedError == nil || err == nil && test.expectedError != nil {
			t.Errorf("Expected error %v, but got %v", test.expectedError, err)
		}

		if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
			t.Errorf("Expected error %v, but got %v", test.expectedError, err)
		}

		if cred.Type != test.expectedCredType {
			t.Errorf("Expected cred_type %v, but got %v", cred_type, cred.Type)
		}
	}
}

type presentVerifiableCredentialTest struct {
}

func TestPresentVerifiableCredential(t *testing.T) {
	t.Skip("Not implemented")
}
