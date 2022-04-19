package knox

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/credential_adapter/mock"
	knox_mock "github.com/knox-networks/knox-go/mock"
)

type requestCredentialFields struct {
	w  Wallet
	ca credential_adapter.CredentialAdapterClient
}
type requestCredentialArgs struct {
	cred_type string
}

type requestCredentialTest struct {
	name          string
	prepare       func(f *requestCredentialFields)
	args          requestCredentialArgs
	expectedError error
}

func TestRequestCredential(t *testing.T) {
	cred_type := "BankCard"
	mock_controller := gomock.NewController(t)
	mock_wallet := knox_mock.NewMockWallet(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	kc := &knoxClient{wallet: mock_wallet, ca: mock_ca}

	tests := []requestCredentialTest{
		{
			name: "RequestCredential Succeeds",
			args: requestCredentialArgs{
				cred_type: cred_type,
			},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*knox_mock.MockWallet).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*knox_mock.MockWallet).EXPECT().
						Sign([]byte(nonce)).
						Return(signature, nil),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						IssueVerifiableCredential(cred_type, did, nonce, signature).
						Return(credential_adapter.VerifiableCredential{}, nil),
				)

			},
			expectedError: nil,
		},
		{
			name: "RequestCredential Create Challenge Fails",
			args: requestCredentialArgs{
				cred_type: cred_type,
			},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				gomock.InOrder(f.w.(*knox_mock.MockWallet).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, errors.New("error creating challenge")),
				)

			},
			expectedError: errors.New("error creating challenge"),
		},
		{
			name: "RequestCredential Sign Nonce Fails",
			args: requestCredentialArgs{
				cred_type: cred_type,
			},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*knox_mock.MockWallet).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*knox_mock.MockWallet).EXPECT().
						Sign([]byte(nonce)).
						Return(signature, errors.New("error signing")),
				)

			},
			expectedError: errors.New("error signing"),
		},
		{
			name: "RequestCredential Sign Nonce Fails",
			args: requestCredentialArgs{
				cred_type: cred_type,
			},
			prepare: func(f *requestCredentialFields) {
				did := "did:example:123456789"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(f.w.(*knox_mock.MockWallet).EXPECT().
					GetDid().Return(did),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreateIssuanceChallenge(cred_type, did).
						Return(credential_adapter.IssuanceChallenge{Nonce: nonce}, nil),
					f.w.(*knox_mock.MockWallet).EXPECT().
						Sign([]byte(nonce)).
						Return(signature, nil),
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						IssueVerifiableCredential(cred_type, did, nonce, signature).
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
			_, err := kc.RequestCredential(test.args.cred_type)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if (err != nil && test.expectedError != nil) && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}
