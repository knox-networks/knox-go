package credential_adapter

import (
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/helpers/slices"
	mock_client "github.com/knox-networks/knox-go/service/credential_adapter/grpc_mock"
	AdapterApi "go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type createIssuanceChallengeTest struct {
	mockNonce              string
	mockClientRequestError error
	expectedChallenge      IssuanceChallenge
	expectedError          error
}

func TestCreateIssuanceChallenge(t *testing.T) {
	did := "did:knox:test"
	cred_type := "test"
	nonce := "rbmtI32kWmVpdv22i4QDEYtFwjIP22W7"
	url := "localhost:5051"
	mock_controller := gomock.NewController(t)

	tests := []createIssuanceChallengeTest{
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
				Endpoint:       "localhost:5051",
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

type createPresentationChallengeFields struct {
	client AdapterApi.AdapterServiceClient
}
type createPresentationChallengeArgs struct {
	credTypes []string
	nonce     string
}

type createPresentationChallengeTest struct {
	name          string
	prepare       func(f *createPresentationChallengeFields, args *createPresentationChallengeArgs)
	expectedError error
	args          *createPresentationChallengeArgs
}

func TestCreatePresentationChallenge(t *testing.T) {
	mock_controller := gomock.NewController(t)

	f := &createPresentationChallengeFields{
		client: mock_client.NewMockAdapterServiceClient(mock_controller),
	}

	tests := []createPresentationChallengeTest{
		{
			name: "CreatePresentationChallenge Succeeds",
			prepare: func(f *createPresentationChallengeFields, args *createPresentationChallengeArgs) {
				f.client.(*mock_client.MockAdapterServiceClient).EXPECT().
					CreatePresentationChallenge(gomock.Any(), &AdapterApi.CreatePresentationChallengeRequest{
						CredentialTypes: slices.Map(args.credTypes, func(credType string) AdapterApi.CredentialType {
							return getCredentialEnumFromName(credType)
						}),
					},
					).
					Return(&AdapterApi.CreatePresentationChallengeResponse{
						Nonce: args.nonce,
					}, nil)
			},
			args: &createPresentationChallengeArgs{
				credTypes: []string{"PermanentResidentCard"},
				nonce:     "12345",
			},
			expectedError: nil,
		},
		{
			name: "CreatePresentationChallenge Fails Due To Server Error",
			prepare: func(f *createPresentationChallengeFields, args *createPresentationChallengeArgs) {
				f.client.(*mock_client.MockAdapterServiceClient).EXPECT().
					CreatePresentationChallenge(gomock.Any(), &AdapterApi.CreatePresentationChallengeRequest{
						CredentialTypes: slices.Map(args.credTypes, func(credType string) AdapterApi.CredentialType {
							return getCredentialEnumFromName(credType)
						}),
					},
					).
					Return(&AdapterApi.CreatePresentationChallengeResponse{}, status.Error(codes.Internal, "Internal Server Error"))
			},
			args: &createPresentationChallengeArgs{
				credTypes: []string{"PermanentResidentCard"},
			},
			expectedError: status.Error(codes.Internal, "Internal Server Error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.prepare(f, test.args)

			adapter_client := &credentialAdapterClient{
				client: f.client,
			}

			challenge, err := adapter_client.CreatePresentationChallenge(test.args.credTypes)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error %v, but got %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, but got %v", test.expectedError, err)
			}

			if test.expectedError != nil && challenge.Nonce != test.args.nonce {
				t.Errorf("Expected nonce %v, but got %v", test.args.nonce, challenge.Nonce)
			}

			if test.expectedError == nil && !reflect.DeepEqual(challenge.CredentialTypes, test.args.credTypes) {
				t.Errorf("Expected credential types %v, got %v", test.args.credTypes, challenge.CredentialTypes)
			}

		})
	}
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
		}).Return(&AdapterApi.IssueVerifiableCredentialResponse{Credential: "{}"}, test.mockClientRequestError)

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

func TestPresentVerifiableCredential(t *testing.T) {
	t.Skip("Not implemented")
}
