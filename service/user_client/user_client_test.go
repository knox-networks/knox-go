package user_client

import (
	"errors"
	"testing"

	UserApi "buf.build/gen/go/knox-networks/user-mgmt/protocolbuffers/go/user_api/v1"
	"github.com/golang/mock/gomock"
	grpc_mock "github.com/knox-networks/knox-go/service/user_client/grpc_mock"

	UserGrpc "buf.build/gen/go/knox-networks/user-mgmt/grpc/go/user_api/v1/user_apiv1grpc"
)

type createDidAuthenticationChallengeFields struct {
	client UserGrpc.UserApiServiceClient
}
type createDidAuthenticationChallengeArgs struct {
	nonce string
	did   string
}

type createDidAuthenticationChallengeTest struct {
	name          string
	prepare       func(f *createDidAuthenticationChallengeFields, args *createDidAuthenticationChallengeArgs)
	expectedError error
	args          *createDidAuthenticationChallengeArgs
}

func TestCreateDidAuthenticationChallenge(t *testing.T) {
	mock_controller := gomock.NewController(t)

	f := &createDidAuthenticationChallengeFields{
		client: grpc_mock.NewMockUserApiServiceClient(mock_controller),
	}

	tests := []createDidAuthenticationChallengeTest{
		{
			name: "CreateDidAuthenticationChallenge Succeeds",
			prepare: func(f *createDidAuthenticationChallengeFields, args *createDidAuthenticationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockUserApiServiceClient).EXPECT().
						CreateAuthnWalletChallenge(gomock.Any(), &UserApi.CreateAuthnWalletChallengeRequest{Did: args.did}).
						Return(&UserApi.CreateAuthnWalletChallengeResponse{Nonce: args.nonce}, nil),
				)
			},
			expectedError: nil,
			args: &createDidAuthenticationChallengeArgs{
				nonce: "nonce",
				did:   "did:knox:test",
			},
		},
		{
			name: "CreateDidAuthenticationChallenge Fails Due To Error Getting Challenge",
			prepare: func(f *createDidAuthenticationChallengeFields, args *createDidAuthenticationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockUserApiServiceClient).EXPECT().
						CreateAuthnWalletChallenge(gomock.Any(), &UserApi.CreateAuthnWalletChallengeRequest{Did: args.did}).
						Return(&UserApi.CreateAuthnWalletChallengeResponse{}, errors.New("challenge error")),
				)
			},
			expectedError: errors.New("challenge error"),
			args: &createDidAuthenticationChallengeArgs{
				nonce: "nonce",
				did:   "did:knox:test",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, test.args)

			c := &userClient{
				client: f.client,
			}
			challenge, err := c.CreateDidAuthenticationChallenge(test.args.did)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if test.expectedError == nil && challenge.Nonce != test.args.nonce {
				t.Errorf("Expected nonce: %v, got: %v", test.args.nonce, challenge.Nonce)
			}

		})
	}

}

type createDidRegistrationChallengeFields struct {
	client        UserGrpc.UserApiServiceClient
	stream_client UserGrpc.UserApiService_CreateRegisterWalletChallengeClient
}
type createDidRegistrationChallengeArgs struct {
	nonce string
	token string
}

type createDidRegistrationChallengeTest struct {
	name          string
	prepare       func(f *createDidRegistrationChallengeFields, args *createDidRegistrationChallengeArgs)
	expectedError error
	args          *createDidRegistrationChallengeArgs
}

func TestCreateDidRegistrationChallenge(t *testing.T) {
	mock_controller := gomock.NewController(t)

	f := &createDidRegistrationChallengeFields{
		client:        grpc_mock.NewMockUserApiServiceClient(mock_controller),
		stream_client: grpc_mock.NewMockUserApiService_CreateRegisterWalletChallengeClient(mock_controller),
	}

	tests := []createDidRegistrationChallengeTest{
		{
			name: "CreateDidRegistrationChallenge Succeeds",
			prepare: func(f *createDidRegistrationChallengeFields, args *createDidRegistrationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockUserApiServiceClient).EXPECT().
						CreateRegisterWalletChallenge(gomock.Any(), &UserApi.CreateRegisterWalletChallengeRequest{}).
						Return(f.stream_client, nil),
					f.stream_client.(*grpc_mock.MockUserApiService_CreateRegisterWalletChallengeClient).EXPECT().
						Recv().Return(&UserApi.CreateRegisterWalletChallengeResponse{
						RegistrationStart: &UserApi.CreateRegisterWalletChallengeResponse_Nonce{Nonce: args.nonce},
					}, nil),
				)
			},
			expectedError: nil,
			args: &createDidRegistrationChallengeArgs{
				nonce: "nonce",
				token: "auth_token",
			},
		},
		{
			name: "CreateDidRegistrationChallenge Fails Due To Error Starting Stream",
			prepare: func(f *createDidRegistrationChallengeFields, args *createDidRegistrationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockUserApiServiceClient).EXPECT().
						CreateRegisterWalletChallenge(gomock.Any(), &UserApi.CreateRegisterWalletChallengeRequest{}).
						Return(f.stream_client, errors.New("stream errror")),
				)
			},
			expectedError: errors.New("stream errror"),
			args: &createDidRegistrationChallengeArgs{
				nonce: "nonce",
				token: "auth_token",
			},
		},
		{
			name: "CreateDidRegistrationChallenge Fails Due To Error Getting Challenge",
			prepare: func(f *createDidRegistrationChallengeFields, args *createDidRegistrationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockUserApiServiceClient).EXPECT().
						CreateRegisterWalletChallenge(gomock.Any(), &UserApi.CreateRegisterWalletChallengeRequest{}).
						Return(f.stream_client, nil),
					f.stream_client.(*grpc_mock.MockUserApiService_CreateRegisterWalletChallengeClient).EXPECT().
						Recv().Return(&UserApi.CreateRegisterWalletChallengeResponse{}, errors.New("challenge error")),
				)
			},
			expectedError: errors.New("challenge error"),
			args: &createDidRegistrationChallengeArgs{
				nonce: "nonce",
				token: "auth_token",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare(f, test.args)

			c := &userClient{
				client: f.client,
			}
			challenge, _, err := c.CreateDidRegistrationChallenge(test.args.token)

			if (err != nil && test.expectedError == nil) || (err == nil && test.expectedError != nil) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}

			if test.expectedError == nil && challenge.Nonce != test.args.nonce {
				t.Errorf("Expected nonce: %v, got: %v", test.args.nonce, challenge.Nonce)
			}

		})
	}

}

func TestAuthenticateWithDid(t *testing.T) {
	t.Skip("TODO: Implement")
}
