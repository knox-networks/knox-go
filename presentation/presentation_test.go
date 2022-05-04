package presentation

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/service/credential_adapter/mock"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
	"github.com/piprate/json-gold/ld"
)

func TestSharePresentation(t *testing.T) {
	credTypes := []string{"PermanentResidentCard"}

	credential := map[string]interface{}{
		"@context": []interface{}{
			"https://www.w3.org/2018/credentials/v1",
		},
		"id": "http://credential_mock:8000/api/credential/z6MkpEo5be7ieVT5VGekfCBkD6L7Mr17KdgcTTA6J1Za6P95",
		"type": []interface{}{
			"VerifiableCredential",
			"PermanentResidentCard",
		},
		"issuer":       "did:knox:z9j11k9soh9kJ1vD9pYR87ZhD7zE1U7ZA3XVSkWjY4YLg",
		"issuanceDate": "2022-05-04T21:47:18Z",
		"credentialSubject": map[string]interface{}{
			"birthCountry":           "Bahamas",
			"birthDate":              "1981-04-01",
			"commuterClassification": "C1",
			"familyName":             "Kim",
			"gender":                 "Male",
			"givenName":              "Francis",
			"id":                     "did:knox:z6MkpEo5be7ieVT5VGekfCBkD6L7Mr17KdgcTTA6J1Za6P95",
			"image":                  "data:image/png;base64,iVBORw0KGgo...kJggg==",
			"lprCategory":            "C09",
			"lprNumber":              "000-000-204",
			"residentSince":          "2015-01-01",
			"type": []interface{}{
				"PermanentResident",
				"Person",
			},
		},
		"proof": map[string]interface{}{
			"type":               "Ed25519Signature2020",
			"created":            "2022-05-04T21:47:18Z",
			"verificationMethod": "did:knox:z9j11k9soh9kJ1vD9pYR87ZhD7zE1U7ZA3XVSkWjY4YLg#z9j11k9soh9kJ1vD9pYR87ZhD7zE1U7ZA3XVSkWjY4YLg",
			"proofPurpose":       "assertionMethod",
			"proofValue":         "z4xTXcWHhZY8oXCXTKSw3N9qmRKjQAUUVbNnQz1FqKCAYiGieYohBRcSKGK9YcBuKqyqzjbaohmtMZBAenC9huBJ",
		},
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = model.NormalizationFormat
	options.Algorithm = model.NormalizationAlgo
	normalized, _ := proc.Normalize(credential, options)

	fmt.Printf("Cred Normalized: %v\n", (normalized.(string)))

	mock_controller := gomock.NewController(t)
	mock_wallet := s_mock.NewMockDynamicSigner(mock_controller)
	mock_ca := ca_mock.NewMockCredentialAdapterClient(mock_controller)
	pc := &presentationClient{s: mock_wallet, ca: mock_ca}
	err := pc.Share(params.SharePresentationParams{
		Credentials: []model.SerializedDocument{credential},
		Challenge: params.SharePresentationChallenge{
			Nonce:           "nonce",
			CredentialTypes: credTypes,
		},
	})

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
