package knox

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/service/credential_adapter"
	ca_mock "github.com/knox-networks/knox-go/service/credential_adapter/mock"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

func TestPresentCredential(t *testing.T) {
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
	kc := &KnoxClient{s: mock_wallet, ca: mock_ca}
	mock_ca.EXPECT().CreatePresentationChallenge().Return(&credential_adapter.PresentationChallenge{}, nil)
	err := kc.SharePresentation(SharePresentationParams{Credentials: []model.SerializedDocument{cred}})

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

}
