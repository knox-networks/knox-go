package identity

import (
	"bytes"
	"errors"
	"github.com/knox-networks/knox-go/model"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/helpers/crypto"
	cm_mock "github.com/knox-networks/knox-go/helpers/crypto/mock"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/registry_client"
	registry_mock "github.com/knox-networks/knox-go/service/registry_client/mock"
	"github.com/knox-networks/knox-go/service/user_client"
	user_mock "github.com/knox-networks/knox-go/service/user_client/mock"
	"github.com/knox-networks/knox-go/signer"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
	"github.com/multiformats/go-multibase"
)

type generateIdentityFields struct {
	cm       crypto.CryptoManager
	registry registry_client.RegistryClient
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
		cm:       mock_cm,
		registry: registry_mock.NewMockRegistryClient(mock_controller),
	}
	tests := []generateIdentityTest{
		{
			name: "GenerateIdentity Succeeds",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {
				mnemonic := "mnemonic"
				publicKey := "publicKey"
				gomock.InOrder(
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateMnemonic().Return(mnemonic, nil),
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair(mnemonic).
						Return(&crypto.KeyPairs{MasterPublicKey: publicKey}, nil),
					f.registry.(*registry_mock.MockRegistryClient).EXPECT().
						Create(crypto.DidPrefix+publicKey, gomock.Any()).Return(nil),
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
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair(mnemonic).
						Return(&crypto.KeyPairs{}, errors.New("error")),
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
		{
			name: "GenerateIdentity Fails Due To Registry Error",
			args: generateIdentityArgs{
				p: params.GenerateIdentityParams{},
			},
			prepare: func(f *generateIdentityFields, args *generateIdentityArgs) {
				mnemonic := "mnemonic"
				publicKey := "publicKey"
				gomock.InOrder(
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateMnemonic().Return(mnemonic, nil),
					f.cm.(*cm_mock.MockCryptoManager).EXPECT().GenerateKeyPair(mnemonic).
						Return(&crypto.KeyPairs{MasterPublicKey: publicKey}, nil),
					f.registry.(*registry_mock.MockRegistryClient).EXPECT().
						Create(crypto.DidPrefix+publicKey, gomock.Any()).Return(errors.New("registry error")),
				)
			},
			expectedError: errors.New("registry error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, &test.args)
			c := &identityClient{cm: f.cm, registry: f.registry}
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
	auth       user_client.UserClient
	authStream user_client.StreamClient
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
		auth:       user_mock.NewMockUserClient(mock_controller),
		signer:     s_mock.NewMockDynamicSigner(mock_controller),
		authStream: user_mock.NewMockStreamClient(mock_controller),
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*user_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(nil),
					f.authStream.(*user_mock.MockStreamClient).EXPECT().Close().Return(nil),
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
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{}, f.authStream, errors.New("challenge error")),
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, errors.New("signing error")),
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
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, errors.New("signing error")),
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
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
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*user_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(errors.New("wait error")),
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
					f.auth.(*user_mock.MockUserClient).EXPECT().
						CreateDidRegistrationChallenge(args.p.Token).
						Return(&user_client.DidRegistrationChallenge{Nonce: nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, []byte(did+"."+nonce)).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).EXPECT().
						AuthnWithDidRegister(did, nonce, signature).
						Return(nil),
					f.authStream.(*user_mock.MockStreamClient).EXPECT().WaitForCompletion().Return(nil),
					f.authStream.(*user_mock.MockStreamClient).EXPECT().Close().Return(errors.New("close error")),
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

type recoverIdentityFields struct {
	cm crypto.CryptoManager
}
type recoverIdentityArgs struct {
	p *params.RecoverIdentityParams
}

type recoverIdentityTest struct {
	name          string
	prepare       func(f *recoverIdentityFields, args *recoverIdentityArgs)
	args          recoverIdentityArgs
	expectedError error
}

func TestRecoverIdentity(t *testing.T) {
	mock_controller := gomock.NewController(t)

	mock_cm := cm_mock.NewMockCryptoManager(mock_controller)
	f := &recoverIdentityFields{
		cm: mock_cm,
	}

	tests := []recoverIdentityTest{
		{
			name: "RecoverIdentity Succeeds",
			args: recoverIdentityArgs{
				p: &params.RecoverIdentityParams{
					Mnemonic: "mnemonic",
				},
			},
			prepare: func(f *recoverIdentityFields, args *recoverIdentityArgs) {
				f.cm.(*cm_mock.MockCryptoManager).EXPECT().
					GenerateKeyPair(args.p.Mnemonic).
					Return(&crypto.KeyPairs{}, nil)
			},
			expectedError: nil,
		},
		{
			name: "RecoverIdentity Fails Due To Key Generation Error",
			args: recoverIdentityArgs{
				p: &params.RecoverIdentityParams{
					Mnemonic: "mnemonic",
				},
			},
			prepare: func(f *recoverIdentityFields, args *recoverIdentityArgs) {
				f.cm.(*cm_mock.MockCryptoManager).EXPECT().
					GenerateKeyPair(args.p.Mnemonic).
					Return(&crypto.KeyPairs{}, errors.New("key generation error"))
			},
			expectedError: errors.New("key generation error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, &test.args)

			c := &identityClient{
				cm: f.cm,
			}

			_, _, err := c.Recover(test.args.p)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error %v, got %v", test.expectedError, err)
			}
		})
	}
}

func TestDeterministicKeyGeneration(t *testing.T) {
	mock_controller := gomock.NewController(t)
	mockReg := registry_mock.NewMockRegistryClient(mock_controller)
	c := &identityClient{
		cm:       crypto.NewCryptoManager(),
		registry: mockReg,
	}

	mockReg.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil)

	doc, kps, _ := c.Generate(&params.GenerateIdentityParams{})

	recoveredDocs, recoveredKeys, _ := c.Recover(&params.RecoverIdentityParams{
		Mnemonic: kps.Mnemonic,
	})

	if doc.Id != recoveredDocs.Id {
		t.Errorf("Expected did %v, got %v", doc.Id, recoveredDocs.Id)
	}

	if !bytes.Equal(kps.MasterPrivateKey, recoveredKeys.MasterPrivateKey) {
		encodedO, _ := multibase.Encode(multibase.Base58BTC, kps.MasterPrivateKey)
		encodedR, _ := multibase.Encode(multibase.Base58BTC, recoveredKeys.MasterPrivateKey)
		t.Errorf("Expected %s, got %s", encodedO, encodedR)
	}

	if !bytes.Equal(kps.AuthenticationPrivateKey, recoveredKeys.AuthenticationPrivateKey) {
		encodedO, _ := multibase.Encode(multibase.Base58BTC, kps.AuthenticationPrivateKey)
		encodedR, _ := multibase.Encode(multibase.Base58BTC, recoveredKeys.AuthenticationPrivateKey)
		t.Errorf("Expected %s, got %s", encodedO, encodedR)
	}

	if !bytes.Equal(kps.CapabilityInvocationPrivateKey, recoveredKeys.CapabilityInvocationPrivateKey) {
		encodedO, _ := multibase.Encode(multibase.Base58BTC, kps.CapabilityInvocationPrivateKey)
		encodedR, _ := multibase.Encode(multibase.Base58BTC, recoveredKeys.CapabilityInvocationPrivateKey)
		t.Errorf("Expected %s, got %s", encodedO, encodedR)
	}

	if !bytes.Equal(kps.CapabilityDelegationPrivateKey, recoveredKeys.CapabilityDelegationPrivateKey) {
		encodedO, _ := multibase.Encode(multibase.Base58BTC, kps.CapabilityDelegationPrivateKey)
		encodedR, _ := multibase.Encode(multibase.Base58BTC, recoveredKeys.CapabilityDelegationPrivateKey)
		t.Errorf("Expected %s, got %s", encodedO, encodedR)
	}

	if !bytes.Equal(kps.AssertionMethodPrivateKey, recoveredKeys.AssertionMethodPrivateKey) {
		encodedO, _ := multibase.Encode(multibase.Base58BTC, kps.AssertionMethodPrivateKey)
		encodedR, _ := multibase.Encode(multibase.Base58BTC, recoveredKeys.AssertionMethodPrivateKey)
		t.Errorf("Expected %s, got %s", encodedO, encodedR)
	}

	if kps.MasterPublicKey != recoveredKeys.MasterPublicKey {
		t.Errorf("Expected %s, got %s", kps.MasterPublicKey, recoveredKeys.MasterPublicKey)
	}

}

func TestRevoke_MarshalDIDDocumentError(t *testing.T) {
	mockController := gomock.NewController(t)
	mockReg := registry_mock.NewMockRegistryClient(mockController)
	c := &identityClient{
		cm:       crypto.NewCryptoManager(),
		registry: mockReg,
	}
	mne, err := c.cm.GenerateMnemonic()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
		return
	}

	kps, err := c.cm.GenerateKeyPair(mne)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
		return
	}

	mockReg.EXPECT().Resolve(kps.GetDid()).Return(&model.DidDocument{}, nil)
	mockReg.EXPECT().Revoke(kps.GetDid(), gomock.Any()).Return(nil)

	p := &params.RevocationIdentityParams{
		Mnemonic: kps.Mnemonic,
		Did:      kps.GetDid(),
	}

	err = c.Revoke(p)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}
