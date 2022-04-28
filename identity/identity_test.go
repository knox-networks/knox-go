package identity

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/helpers/crypto"
	cm_mock "github.com/knox-networks/knox-go/helpers/crypto/mock"
	"github.com/knox-networks/knox-go/params"
)

type generateIdentityFields struct {
	cm crypto.CryptoManager
}
type generateIdentityArgs struct {
	p params.GenerateIdentityParams
}

type generateIdentityTest struct {
	name          string
	prepare       func(f *generateIdentityFields, args *generateIdentityArgs)
	args          generateIdentityArgs
	expectedError error
}

func TestGenerateIdentity(t *testing.T) {
	mock_controller := gomock.NewController(t)
	mock_cm := cm_mock.NewMockCryptoManager(mock_controller)
	f := &generateIdentityFields{
		cm: mock_cm,
	}
	tests := []generateIdentityTest{
		{
			name: "GenerateIdentity Succeeds",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare:       func(f *generateIdentityFields, args *generateIdentityArgs) {},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, &test.args)

			c := &identityClient{}
			_, _, err := c.Generate(params.GenerateIdentityParams{})

			if err != test.expectedError {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}

func TestRegisterIdentity(t *testing.T) {
	t.Skip("not implemented")
}
