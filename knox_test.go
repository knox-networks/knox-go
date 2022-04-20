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

func TestPresentCredential(t *testing.T) {
	cred := []byte(`{"@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"id":"http://credential_mock:8000/api/credential/z6MkmE7owsRZ5RdvAB83LyDYqgKTNsQk2F8832H1rAAdVNWt","type":["VerifiableCredential","BankCard"],"issuer":"did:knox:12345","issuanceDate":"2022-04-15T18:54:50Z","subject":{"account":"000-000-204","address":"19 Knox St, Toronto, ON","birthDate":"1981-04-01","branch":"C09","country":"Canada","familyName":"Kim","gender":"Male","givenName":"Francis","id":"did:knox:z6MkmE7owsRZ5RdvAB83LyDYqgKTNsQk2F8832H1rAAdVNWt","phone":"416-984-1234","type":["BankCard"]},"proof":{"type":"Ed25519Signature2020","created":"2022-04-15T18:54:50Z","verificationMethod":"did:knox:12345#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY","proofPurpose":"assertionMethod","proofValue":"z93NYjED6qSfNoA43h8KXVbNn4e7UcYuFGLLdLxVYJWCS5jgnEXfthYp1LHmAohDAgAngdQcTZCX1aBWbnX81bkC"}}`)

	mock_controller := gomock.NewController(t)
	mock_wallet := knox_mock.NewMockWallet(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	kc := &knoxClient{wallet: mock_wallet, ca: mock_ca}
	mock_ca.EXPECT().CreatePresentationChallenge().Return(&credential_adapter.PresentationChallenge{}, nil)
	err := kc.PresentCredential(cred)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

}
