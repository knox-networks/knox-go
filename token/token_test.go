package token

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/user_client"
	user_mock "github.com/knox-networks/knox-go/service/user_client/mock"
	"github.com/knox-networks/knox-go/signer"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
)

type createTokenFields struct {
	auth   user_client.UserClient
	signer signer.DynamicSigner
}
type createTokenArgs struct {
	p     *params.CreateTokenParams
	nonce string
}

type createTokenTest struct {
	name          string
	prepare       func(f *createTokenFields, args *createTokenArgs)
	args          createTokenArgs
	expectedError error
}

func TestCreateToken(t *testing.T) {
	mockController := gomock.NewController(t)
	f := &createTokenFields{
		auth:   user_mock.NewMockUserClient(mockController),
		signer: s_mock.NewMockDynamicSigner(mockController),
	}
	tests := []createTokenTest{
		{
			name: "CreateToken With Did Authentication Succeeds",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						CreateDidAuthenticationChallenge(args.p.Did.Did).
						Return(&user_client.DidAuthenticationChallenge{
							Nonce: args.nonce,
						}, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						AuthenticateWithDid(args.p.Did.Did, args.nonce, signature).
						Return(&model.AuthToken{}, nil),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Did: &params.DidAuthentication{
						Did: "did:knox:test",
					},
				},
				nonce: "nonce",
			},
			expectedError: nil,
		},
		{
			name: "CreateToken With Did Authentication Fails Creating Challenge",
			prepare: func(f *createTokenFields, args *createTokenArgs) {

				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						CreateDidAuthenticationChallenge(args.p.Did.Did).
						Return(&user_client.DidAuthenticationChallenge{}, errors.New("challenge error")),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Did: &params.DidAuthentication{
						Did: "did:knox:test",
					},
				},
			},
			expectedError: errors.New("challenge error"),
		},
		{
			name: "CreateToken With Did Authentication Fails Creating Signature",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						CreateDidAuthenticationChallenge(args.p.Did.Did).
						Return(&user_client.DidAuthenticationChallenge{Nonce: args.nonce}, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{}, errors.New("signature error")),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Did: &params.DidAuthentication{
						Did: "did:knox:test",
					},
				},
				nonce: "nonce",
			},
			expectedError: errors.New("signature error"),
		},
		{
			name: "CreateToken With Did Authentication Fails Authenticating Against Service",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						CreateDidAuthenticationChallenge(args.p.Did.Did).
						Return(&user_client.DidAuthenticationChallenge{Nonce: args.nonce}, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						AuthenticateWithDid(args.p.Did.Did, args.nonce, signature).
						Return(&model.AuthToken{}, errors.New("authentication error")),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Did: &params.DidAuthentication{
						Did: "did:knox:test",
					},
				},
				nonce: "nonce",
			},
			expectedError: errors.New("authentication error"),
		},
		{
			name: "CreateToken Fails Due To Neither Did Nor Password Authentication Provided",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{},
			},
			expectedError: errors.New("no authentication method specified"),
		},
		{
			name: "CreateToken With Password Authentication Succeeds",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().AuthenticateWithPassword(args.p.Password.Email, args.p.Password.Password).
						Return(&model.AuthToken{
							Token: "token",
						}, nil),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Password: &params.PasswordAuthentication{
						Email:    "testuser@email.com",
						Password: "123445667",
					},
				},
				nonce: "nonce",
			},
			expectedError: nil,
		},
		{
			name: "CreateToken With Password Authentication Fails Due To Authentication Error",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				gomock.InOrder(
					f.auth.(*user_mock.MockUserClient).
						EXPECT().AuthenticateWithPassword(args.p.Password.Email, args.p.Password.Password).
						Return(&model.AuthToken{}, errors.New("authentication error")),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Password: &params.PasswordAuthentication{
						Email:    "testuser@email.com",
						Password: "123445667",
					},
				},
				nonce: "nonce",
			},
			expectedError: errors.New("authentication error"),
		},
		{
			name: "CreateToken With Did Authentication Succeeds With Pre-Existing Challenge",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*user_mock.MockUserClient).
						EXPECT().
						AuthenticateWithDid(args.p.Did.Did, args.nonce, signature).
						Return(&model.AuthToken{}, nil),
				)
			},
			args: createTokenArgs{
				p: &params.CreateTokenParams{
					Did: &params.DidAuthentication{
						Did: "did:knox:test",
						Challenge: &params.DidAuthenticationChallenge{
							Nonce: "nonce",
						},
					},
				},
			},
			expectedError: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.prepare(f, &test.args)
			client := tokenClient{
				auth: f.auth,
				s:    f.signer,
			}

			_, err := client.Create(test.args.p)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}
		})
	}
}

func TestNewTokenClient(t *testing.T) {
	mockController := gomock.NewController(t)

	signer := s_mock.NewMockDynamicSigner(mockController)

	_, err := NewTokenClient("localhost:5051", signer)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}
