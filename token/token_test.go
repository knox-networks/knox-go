package token

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/knox-networks/knox-go/model"
	"github.com/knox-networks/knox-go/params"
	"github.com/knox-networks/knox-go/service/auth_client"
	grpc_auth_mock "github.com/knox-networks/knox-go/service/auth_client/grpc_mock"
	auth_mock "github.com/knox-networks/knox-go/service/auth_client/mock"
	"github.com/knox-networks/knox-go/signer"
	s_mock "github.com/knox-networks/knox-go/signer/mock"
	AuthApi "go.buf.build/grpc/go/knox-networks/auth-mgmt/auth_api/v1"
)

type createTokenFields struct {
	auth       auth_client.AuthClient
	authStream AuthApi.AuthApiService_AuthnWithDidStartClient
	signer     signer.DynamicSigner
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
		auth:       auth_mock.NewMockAuthClient(mockController),
		signer:     s_mock.NewMockDynamicSigner(mockController),
		authStream: grpc_auth_mock.NewMockAuthApiService_AuthnWithDidStartClient(mockController),
	}
	tests := []createTokenTest{
		{
			name: "CreateToken With Did Authentication Succeeds",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{
							Nonce: args.nonce,
						}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						AuthnWithDid(args.p.Did.Did, args.nonce, signature).
						Return(nil),
					f.authStream.(*grpc_auth_mock.MockAuthApiService_AuthnWithDidStartClient).
						EXPECT().Recv().Return(&AuthApi.AuthnWithDidStartResponse{
						DidStart: &AuthApi.AuthnWithDidStartResponse_AuthToken{
							AuthToken: &AuthApi.AuthTokenResponse{
								AuthToken: &AuthApi.AuthToken{
									Token: "token",
								},
							},
						},
					}, nil),
					f.authStream.(*grpc_auth_mock.MockAuthApiService_AuthnWithDidStartClient).
						EXPECT().CloseSend().Return(nil),
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
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{}, f.authStream, errors.New("challenge error")),
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
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{Nonce: args.nonce}, f.authStream, nil),
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
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{Nonce: args.nonce}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						AuthnWithDid(args.p.Did.Did, args.nonce, signature).
						Return(errors.New("authentication error")),
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
			name: "CreateToken With Did Authentication Fails To Receive Message",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{
							Nonce: args.nonce,
						}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						AuthnWithDid(args.p.Did.Did, args.nonce, signature).
						Return(nil),
					f.authStream.(*grpc_auth_mock.MockAuthApiService_AuthnWithDidStartClient).
						EXPECT().Recv().Return(&AuthApi.AuthnWithDidStartResponse{}, errors.New("receive error")),
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
			expectedError: errors.New("receive error"),
		},
		{
			name: "CreateToken With Did Authentication Fails To Close Stream",
			prepare: func(f *createTokenFields, args *createTokenArgs) {
				signature := []byte("signature")
				message := []byte(args.p.Did.Did + "." + args.nonce)
				gomock.InOrder(
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						CreateDidAuthenticationChallenge().
						Return(&auth_client.DidAuthenticationChallenge{
							Nonce: args.nonce,
						}, f.authStream, nil),
					f.signer.(*s_mock.MockDynamicSigner).EXPECT().
						Sign(signer.Authentication, message).
						Return(&signer.SigningResponse{ProofValue: signature}, nil),
					f.auth.(*auth_mock.MockAuthClient).
						EXPECT().
						AuthnWithDid(args.p.Did.Did, args.nonce, signature).
						Return(nil),
					f.authStream.(*grpc_auth_mock.MockAuthApiService_AuthnWithDidStartClient).
						EXPECT().Recv().Return(&AuthApi.AuthnWithDidStartResponse{
						DidStart: &AuthApi.AuthnWithDidStartResponse_AuthToken{
							AuthToken: &AuthApi.AuthTokenResponse{
								AuthToken: &AuthApi.AuthToken{
									Token: "token",
								},
							},
						},
					}, nil),
					f.authStream.(*grpc_auth_mock.MockAuthApiService_AuthnWithDidStartClient).
						EXPECT().CloseSend().Return(errors.New("close error")),
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
			expectedError: errors.New("close error"),
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
					f.auth.(*auth_mock.MockAuthClient).
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
					f.auth.(*auth_mock.MockAuthClient).
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

	_, err := NewTokenClient("", signer)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}
