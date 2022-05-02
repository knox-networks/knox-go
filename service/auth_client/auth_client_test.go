package auth_client

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	grpc_mock "github.com/knox-networks/knox-go/service/auth_client/grpc_mock"
	AuthApi "go.buf.build/grpc/go/knox-networks/auth-mgmt/auth_api/v1"
)

type createDidRegistrationChallengeFields struct {
	client        AuthApi.AuthApiServiceClient
	stream_client AuthApi.AuthApiService_AuthnWithDidRegisterStartClient
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
		client:        grpc_mock.NewMockAuthApiServiceClient(mock_controller),
		stream_client: grpc_mock.NewMockAuthApiService_AuthnWithDidRegisterStartClient(mock_controller),
	}

	tests := []createDidRegistrationChallengeTest{
		{
			name: "CreateDidRegistrationChallenge Succeeds",
			prepare: func(f *createDidRegistrationChallengeFields, args *createDidRegistrationChallengeArgs) {
				gomock.InOrder(
					f.client.(*grpc_mock.MockAuthApiServiceClient).EXPECT().
						AuthnWithDidRegisterStart(gomock.Any(), &AuthApi.AuthnWithDidRegisterStartRequest{}).
						Return(f.stream_client, nil),
					f.stream_client.(*grpc_mock.MockAuthApiService_AuthnWithDidRegisterStartClient).EXPECT().
						Recv().Return(&AuthApi.AuthnWithDidRegisterStartResponse{
						RegistrationStart: &AuthApi.AuthnWithDidRegisterStartResponse_Nonce{Nonce: args.nonce},
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
					f.client.(*grpc_mock.MockAuthApiServiceClient).EXPECT().
						AuthnWithDidRegisterStart(gomock.Any(), &AuthApi.AuthnWithDidRegisterStartRequest{}).
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
					f.client.(*grpc_mock.MockAuthApiServiceClient).EXPECT().
						AuthnWithDidRegisterStart(gomock.Any(), &AuthApi.AuthnWithDidRegisterStartRequest{}).
						Return(f.stream_client, nil),
					f.stream_client.(*grpc_mock.MockAuthApiService_AuthnWithDidRegisterStartClient).EXPECT().
						Recv().Return(&AuthApi.AuthnWithDidRegisterStartResponse{}, errors.New("challenge error")),
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

			c := &authClient{
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
