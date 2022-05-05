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
	"github.com/knox-networks/knox-go/signer"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
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
				mnemonic := "mnemonic"
				gomock.InOrder(
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateMnemonic().Return(mnemonic, nil),
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair(mnemonic).Return(&crypto.KeyPairs{}, nil),
				)
			},
			expectedError: nil,
		},
		{
			name: "GenerateIdentity Fails Due To Key Generation Error",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {
				mnemonic := "mnemonic"
				gomock.InOrder(
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateMnemonic().Return(mnemonic, nil),
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair(mnemonic).Return(&crypto.KeyPairs{}, errors.New("error")),
				)
			},
			expectedError: errors.New("error"),
		},
		{
			name: "GenerateIdentity Fails Due To Mnemonic Generation Error",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {
				f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateMnemonic().Return("", errors.New("mnemonic error"))
			},
			expectedError: errors.New("mnemonic error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, &test.args)
			c := &identityClient{cm: f.cm}
			_, _, err := c.Generate(&params.GenerateIdentityParams{})

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}

type registerIdentityFields struct {
	cm         crypto.CryptoManager
	auth       auth_client.AuthClient
	authStream auth_client.StreamClient
	signer     signer.DynamicSigner
}
type registerIdentityArgs struct {
	p *params.RegisterIdentityParams
}

type registerIdentityTest struct {
	name          string
	prepare       func(f *registerIdentityFields, args *registerIdentityArgs)
	args          registerIdentityArgs
	expectedError error
}

func TestRegisterIdentity(t *testing.T) {
	mock_controller := gomock.NewController(t)
	f := &registerIdentityFields{
		cm:         cm_mock.NewMockCryptoManager(mock_controller),
		auth:       auth_mock.NewMockAuthClient(mock_controller),
		signer:     s_mock.NewMockDynamicSigner(mock_controller),
		authStream: auth_mock.NewMockStreamClient(mock_controller),
	}
	tests := []registerIdentityTest{
		{
			name: "RegisterIdentity Succeeds With",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*auth_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(nil),
					f.authStream.(*auth_mock.MockStreamClient).EXPECT().Close().Return(nil),
				)
			},
			expectedError: nil,
		},
		{
			name: "RegisterIdentity Succeeds With Pre-Existing Challenge",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Challenge: &params.RegisterIdentityChallenge{
						Nonce: "nonce",
					},
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := args.p.Challenge.Nonce
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
				)
			},
			expectedError: nil,
		},
		{
			name: "RegisterIdentity Succeeds Fails Due To Error Creating Challenge",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{}, f.authStream, errors.New("challenge error")),
				)
			},
			expectedError: errors.New("challenge error"),
		},
		{
			name: "RegisterIdentity Fails Due To Signing Error",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, errors.New("signing error")),
				)
			},
			expectedError: errors.New("signing error"),
		},
		{
			name: "RegisterIdentity Pre-Existing Challenge Fails Due To Signing Error",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Challenge: &params.RegisterIdentityChallenge{
						Nonce: "nonce",
					},
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, errors.New("signing error")),
				)
			},
			expectedError: errors.New("signing error"),
		},
		{
			name: "RegisterIdentity Fails Due To AuthnWithDidRegister Error",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(errors.New("registration error")),
				)
			},
			expectedError: errors.New("registration error"),
		},
		{
			name: "RegisterIdentity Pre-Existing Challenge Fails Due To AuthnWithDidRegister Error",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Challenge: &params.RegisterIdentityChallenge{
						Nonce: "nonce",
					},
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(errors.New("registration error")),
				)
			},
			expectedError: errors.New("registration error"),
		},
		{
			name: "RegisterIdentity Fails Due To WaitForComplete Error",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*auth_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(errors.New("wait error")),
				)
			},
			expectedError: errors.New("wait error"),
		},
		{
			name: "RegisterIdentity Fails While Closing Stream",
			args: registerIdentityArgs{
				p: &params.RegisterIdentityParams{
					Token: "token",
				},
			},
			prepare: func(f *registerIdentityFields, args *registerIdentityArgs) {
				did := "did:knox:test"
				nonce := "nonce"
				signature := []byte("signature")
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().GetDid().Return(did),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&auth_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).Return(signature, nil),
					f.auth.(*auth_mock.MockAuthClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*auth_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(nil),
					f.authStream.(*auth_mock.MockStreamClient).EXPECT().Close().Return(errors.New("close error")),
				)
			},
			expectedError: errors.New("close error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			c := &identityClient{
				cm:   f.cm,
				auth: f.auth,
				s:    f.signer,
			}

			test.prepare(f, &test.args)

			err := c.Register(test.args.p)

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
