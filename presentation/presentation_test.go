package presentation

import (
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/service/credential_adapter/mock"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

func TestSharePresentation(t *testing.T) {
	cred_types := []string{"PermanentResidentCard"}
	cred := []byte(`{
		"@context":[
		   "https://www.w3.org/2018/credentials/v1"
		],
		"type":[
		   "VerifiablePresentation"
		],
		"verifiableCredential":[
		   {
			  "@context":[
				 "https://www.w3.org/2018/credentials/v1",
				 "https://w3id.org/citizenship/v1"
			  ],
			  "credentialSubject":{
				 "birthCountry":"Bahamas",
				 "birthDate":"1958-07-17",
				 "commuterClassification":"C1",
				 "familyName":"SMITH",
				 "gender":"Male",
				 "givenName":"JOHN",
				 "id":"did:example:b34ca6cd37bbf23",
				 "image":"data:image/png;base64,iVBORw0KGgo...kJggg==",
				 "lprCategory":"C09",
				 "lprNumber":"999-999-999",
				 "residentSince":"2015-01-01",
				 "type":[
					"PermanentResident",
					"Person"
				 ]
			  },
			  "description":"Government of Example Permanent Resident Card.",
			  "expirationDate":"2029-12-03T12:19:52Z",
			  "id":"https://issuer.oidp.uscis.gov/credentials/83627465",
			  "identifier":"83627465",
			  "issuanceDate":"2019-12-03T12:19:52Z",
			  "issuer":"did:example:28394728934792387",
			  "name":"Permanent Resident Card",
			  "proof":{
				 "created":"2020-01-30T03:32:15Z",
				 "jws":"eyJhbGciOiJFZERTQSIsI...wRG2fNmAx60Vi4Ag",
				 "proofPurpose":"assertionMethod",
				 "type":"Ed25519Signature2018",
				 "verificationMethod":"did:example:28394728934792387#keys-7f83he7s8"
			  },
			  "type":[
				 "VerifiableCredential",
				 "PermanentResidentCard"
			  ]
		   }
		]
	 }`)

	mock_controller := gomock.NewController(t)
	mock_wallet := s_mock.NewMockDynamicSigner(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	pc := &presentationClient{s: mock_wallet, ca: mock_ca}
	mock_ca.EXPECT().CreatePresentationChallenge(cred_types).Return(&credential_adapter.PresentationChallenge{}, nil)
	err := pc.Share(params.SharePresentationParams{Credentials: []model.SerializedDocument{cred}})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

}

type requestPresentationFields struct {
	ca credential_adapter.CredentialAdapterClient
}
type requestPresentationArgs struct {
	credTypes []string
	nonce     string
}

type requestPresentationTest struct {
	name          string
	prepare       func(f *requestPresentationFields, args *requestPresentationArgs)
	expectedError error
	args          *requestPresentationArgs
}

func TestRequestPresentation(t *testing.T) {
	mock_controller := gomock.NewController(t)
	f := &requestPresentationFields{
		ca: ca_mock.NewMockCredentialAdapterClient(mock_controller),
	}

	tests := []requestPresentationTest{
		{
			name:          "RequestPresentation Succeeds",
			expectedError: nil,
			prepare: func(f *requestPresentationFields, args *requestPresentationArgs) {
				gomock.InOrder(
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreatePresentationChallenge(args.credTypes).
						Return(&credential_adapter.PresentationChallenge{
							Nonce:           args.nonce,
							CredentialTypes: args.credTypes,
						}, nil),
				)
			},
			args: &requestPresentationArgs{
				credTypes: []string{"PermanentResidentCard"},
			},
		},
		{
			name:          "RequestPresentation Fails Due To CreatePresentationChallenge Error",
			expectedError: errors.New("CreatePresentationChallenge Error"),
			prepare: func(f *requestPresentationFields, args *requestPresentationArgs) {
				gomock.InOrder(
					f.ca.(*ca_mock.MockCredentialAdapterClient).EXPECT().
						CreatePresentationChallenge(args.credTypes).
						Return(&credential_adapter.PresentationChallenge{}, errors.New("CreatePresentationChallenge Error")),
				)
			},
			args: &requestPresentationArgs{
				credTypes: []string{"PermanentResidentCard"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.prepare(f, test.args)
			pc := &presentationClient{ca: f.ca}
			challenge, err := pc.Request(params.RequestPresentationParams{
				CredentialTypes: test.args.credTypes,
			})
			if (err == nil && test.expectedError != nil) || (err != nil && test.expectedError == nil) {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil {
				if err.Error() != test.expectedError.Error() {
					t.Errorf("Expected error %v, got %v", test.expectedError, err)
				}
			}

			if test.expectedError == nil && challenge.Nonce != test.args.nonce {
				t.Errorf("Expected nonce %s, got %s", test.args.nonce, challenge.Nonce)
			}

			if test.expectedError == nil && !reflect.DeepEqual(challenge.CredentialTypes, test.args.credTypes) {
				t.Errorf("Expected credential types %v, got %v", test.args.credTypes, challenge.CredentialTypes)
			}
		})
	}
}
