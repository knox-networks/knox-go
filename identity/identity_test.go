package identity

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/helpers/crypto"
	cm_mock "github.com/knox-networks/knox-go/helpers/crypto/mock"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	auth_mock "github.com/knox-networks/knox-go/service/auth_client/mock"
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
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {

				f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair().Return(&crypto.KeyPairs{}, nil)
			},
			expectedError: nil,
		},
		{
			name: "GenerateIdentity Fails Due To Key Generation Error",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {

				f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair().Return(&crypto.KeyPairs{}, errors.New("error"))
			},
			expectedError: errors.New("error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, &test.args)
			c := &identityClient{cm: f.cm}
			_, _, err := c.Generate(params.GenerateIdentityParams{})

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}

type registerIdentityields struct {
	cm   crypto.CryptoManager
	auth auth_client.AuthClient
}
type registerIdentityArgs struct {
	p params.RegisterIdentityParams
}

type registerIdentityTest struct {
	name          string
	prepare       func(f *registerIdentityields, args *registerIdentityArgs)
	args          registerIdentityArgs
	expectedError error
}

func TestRegisterIdentity(t *testing.T) {
	mock_controller := gomock.NewController(t)
	f := &registerIdentityields{
		cm:   cm_mock.NewMockCryptoManager(mock_controller),
		auth: auth_mock.NewMockAuthClient(mock_controller),
	}
	tests := []registerIdentityTest{
		{
			name: "RegisterIdentity Succeeds",
			args: registerIdentityArgs{
				p: params.RegisterIdentityParams{},
			},
			prepare: func(f *registerIdentityields, args *registerIdentityArgs) {
			},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			c := &identityClient{
				cm:   f.cm,
				auth: f.auth,
			}

			err := c.Register(params.RegisterIdentityParams{})

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
	t.Skip("not implemented")
}
