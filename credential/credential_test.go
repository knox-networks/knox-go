package credential

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/service/credential_adapter/mock"
	"github.com/knox-networks/knox-go/signer"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

type requestCredentialFields struct {
	w  signer.DynamicSigner
	ca credential_adapter.CredentialAdapterClient
}
type requestCredentialArgs struct {
	p params.RequestCredentialParams
}

type requestCredentialTest struct {
	name          string
	prepare       func(f *requestCredentialFields)
	args          requestCredentialArgs
	expectedError error
}

func TestRequestCredential(t *testing.T) {
	cred_type := "BankCard"
	access_token := "placeholder"
	mock_controller := gomock.NewController(t)
	mock_wallet := s_mock.NewMockDynamicSigner(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	credClient := &credentialClient{s: mock_wallet, ca: mock_ca}

	tests := []requestCredentialTest{
		{
			name: "RequestCredential Succeeds",
			args: requestCredentialArgs{
				p: params.RequestCredentialParams{
					CredentialType: cred_type,
					AccessToken:    access_token,
				},
			},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*s_mock.MockDynamicSigner).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did, access_token).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.AssertionMethod, []byte(nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						IssueVerifiableCredential(cred_type, did, nonce, signature, access_token).
						Return(credential_adapter.VerifiableCredential{}, nil),
				)

			},
			expectedError: nil,
		},
		{
			name: "RequestCredential Succeeds With Pre-Existing Challenge",
			args: requestCredentialArgs{
				p: params.RequestCredentialParams{
					CredentialType: cred_type,
					Challenge: params.RequestCredentialChallenge{
						Nonce: "nonce1234",
					},
					AccessToken: access_token,
				}},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				signature := []byte("signature")
				nonce := "nonce1234"
				gomock.InOrder(f.w.(*s_mock.MockDynamicSigner).EXPECT().
					GetDid().Return(did),
					f.w.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.AssertionMethod, []byte(nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						IssueVerifiableCredential(cred_type, did, nonce, signature, access_token).
						Return(credential_adapter.VerifiableCredential{}, nil),
				)

			},
			expectedError: nil,
		},
		{
			name: "RequestCredential Create Challenge Fails",
			args: requestCredentialArgs{
				p: params.RequestCredentialParams{
					CredentialType: cred_type,
					AccessToken:    access_token,
				}},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				gomock.InOrder(f.w.(*s_mock.MockDynamicSigner).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did, access_token).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, errors.New("error creating challenge")),
				)

			},
			expectedError: errors.New("error creating challenge"),
		},
		{
			name: "RequestCredential Sign Nonce Fails",
			args: requestCredentialArgs{
				p: params.RequestCredentialParams{
					CredentialType: cred_type,
					AccessToken:    access_token,
				}},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*s_mock.MockDynamicSigner).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did, access_token).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.AssertionMethod, []byte(nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, errors.New("error signing")),
				)

			},
			expectedError: errors.New("error signing"),
		},
		{
			name: "RequestCredential Sign Nonce Fails",
			args: requestCredentialArgs{
				p: params.RequestCredentialParams{
					CredentialType: cred_type,
					AccessToken:    access_token,
				}},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*s_mock.MockDynamicSigner).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did, access_token).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.AssertionMethod, []byte(nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						IssueVerifiableCredential(cred_type, did, nonce, signature, access_token).
						Return(credential_adapter.VerifiableCredential{}, errors.New("error issuing credential")),
				)

			},
			expectedError: errors.New("error issuing credential"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &requestCredentialFields{
				w:  mock_wallet,
				ca: mock_ca,
			}
			test.prepare(f)
			_, err := credClient.Request(test.args.p)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if (err != nil && test.expectedError != nil) && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}
