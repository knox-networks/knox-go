package knox

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/credential_adapter/mock"
	knox_mock "github.com/knox-networks/knox-go/mock"
	"github.com/knox-networks/knox-go/model"
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
	cred := model.VerifiableCredential{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/citizenship/v1"},
		Id:           "https://issuer.oidp.uscis.gov/credentials/83627465",
		Type:         []string{"VerifiableCredential", "PermanentResidentCard"},
		Issuer:       "did:example:123456789",
		IssuanceDate: "2020-01-01T00:00:00Z",
		Subject: map[string]interface{}{
			"id":                     "did:example:b34ca6cd37bbf23",
			"type":                   []string{"PermanentResident", "Person"},
			"givenName":              "JOHN",
			"familyName":             "SMITH",
			"gender":                 "Male",
			"image":                  "data:image/png;base64,iVBORw0KGgo...kJggg==",
			"residentSince":          "2015-01-01",
			"lprCategory":            "C09",
			"lprNumber":              "999-999-999",
			"commuterClassification": "C1",
			"birthCountry":           "Bahamas",
			"birthDate":              "1958-07-17",
		},
		Proof: &model.Proof{
			Type:               "Ed25519Signature2020",
			Created:            "2020-01-01T00:00:00Z",
			VerificationMethod: "did:example:123456789#key1",
			ProofPurpose:       "assertionMethod",
			ProofValue:         "signature",
		},
	}

	mock_controller := gomock.NewController(t)
	mock_wallet := knox_mock.NewMockWallet(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	kc := &knoxClient{wallet: mock_wallet, ca: mock_ca}
	mock_ca.EXPECT().CreatePresentationChallenge().Return(&credential_adapter.PresentationChallenge{}, nil)
	err := kc.PresentCredential(cred)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// t.Error("fake error")

}
