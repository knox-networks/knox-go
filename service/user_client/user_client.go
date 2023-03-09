package user_client

import (
	"context"
	"crypto/tls"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/knox-networks/knox-go/model"
	UserApi "go.buf.build/grpc/go/knox-networks/user-mgmt/user_api/v1"

	"google.golang.org/grpc"
)

const DefaultTimeout = 5 * time.Second

type userClient struct {
	client UserApi.UserApiServiceClient
	conn   *grpc.ClientConn
}

type streamClient struct {
	stream grpc.ClientStream
}

type StreamClient interface {
	WaitForCompletion() error
	Close() error
}

type DidRegistrationChallenge struct {
	Nonce string
}

type DidAuthenticationChallenge struct {
	Nonce string
}

type UserClient interface {
	Close()
	AuthenticateWithPassword(email string, password string) (*model.AuthToken, error)
	AuthnWithDidRegister(did string, nonce string, enc []byte) error
	AuthenticateWithDid(did string, nonce string, signature []byte) (*model.AuthToken, error)
	CreateDidAuthenticationChallenge(did string) (*DidAuthenticationChallenge, error)
	CreateDidRegistrationChallenge(auth_token string) (*DidRegistrationChallenge, StreamClient, error)
}

func NewAuthClient(address string) (UserClient, error) {
	var opts []grpc.DialOption
	tlsConfig := &tls.Config{}

	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}
	client := UserApi.NewUserApiServiceClient(conn)
	return &userClient{
		conn:   conn,
		client: client,
	}, nil
}

func NewAuthStream(s grpc.ClientStream) StreamClient {
	return &streamClient{stream: s}
}

func (r *userClient) Close() {
	defer r.conn.Close()
}

func (r *userClient) AuthenticateWithPassword(email string, password string) (*model.AuthToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	req := &UserApi.AuthnWithPasswordRequest{
		Email:    email,
		Password: password,
	}

	res, err := r.client.AuthnWithPassword(ctx, req)
	if err != nil {
		return &model.AuthToken{}, err
	}

	return &model.AuthToken{
		Token:        res.AuthToken.Token,
		TokenType:    res.AuthToken.TokenType,
		ExpiresIn:    res.AuthToken.ExpiresIn,
		RefreshToken: res.AuthToken.RefreshToken,
	}, nil
}

func (r *userClient) CreateDidRegistrationChallenge(auth_token string) (*DidRegistrationChallenge, StreamClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	req := &UserApi.CreateRegisterWalletChallengeRequest{}
	respClient, err := r.client.CreateRegisterWalletChallenge(ctx, req)

	if err != nil {
		return &DidRegistrationChallenge{}, NewAuthStream(respClient), err
	}

	resp, err := respClient.Recv()
	if err != nil {
		return &DidRegistrationChallenge{}, NewAuthStream(respClient), err
	}

	return &DidRegistrationChallenge{Nonce: resp.GetNonce()}, NewAuthStream(respClient), nil
}

func (r *userClient) AuthnWithDidRegister(did string, nonce string, enc []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	req := &UserApi.RegisterWalletRequest{
		Did:       did,
		Nonce:     nonce,
		Signature: enc,
	}

	_, err := r.client.RegisterWallet(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

func (r *userClient) CreateDidAuthenticationChallenge(did string) (*DidAuthenticationChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	req := &UserApi.CreateAuthnWalletChallengeRequest{Did: did}
	resp, err := r.client.CreateAuthnWalletChallenge(ctx, req)
	if err != nil {
		return &DidAuthenticationChallenge{}, err
	}

	return &DidAuthenticationChallenge{Nonce: resp.Nonce}, nil
}

func (r *userClient) AuthenticateWithDid(did string, nonce string, enc []byte) (*model.AuthToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	req := &UserApi.AuthnWalletRequest{
		Did:       did,
		Nonce:     nonce,
		Signature: enc,
	}

	res, err := r.client.AuthnWallet(ctx, req)
	if err != nil {
		return &model.AuthToken{}, err
	}

	return &model.AuthToken{
		Token:        res.AuthToken.Token,
		TokenType:    res.AuthToken.TokenType,
		ExpiresIn:    res.AuthToken.ExpiresIn,
		RefreshToken: res.AuthToken.RefreshToken,
	}, nil
}

func (s *streamClient) WaitForCompletion() error {
	err := s.stream.RecvMsg(nil)
	if err != nil {
		return err
	}

	return nil
}

func (s *streamClient) Close() error {
	return s.stream.CloseSend()
}
