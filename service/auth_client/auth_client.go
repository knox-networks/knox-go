package auth_client

import (
	"context"
	"time"

	"github.com/knox-networks/knox-go/model"
	"google.golang.org/grpc/credentials/insecure"

	AuthApi "go.buf.build/grpc/go/knox-networks/auth-mgmt/auth_api/v1"

	"google.golang.org/grpc"
)

type authClient struct {
	client AuthApi.AuthApiServiceClient
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

type AuthClient interface {
	Close()
	AuthenticateWithPassword(email string, password string) (*model.AuthToken, error)
	AuthnWithDidRegister(did string, nonce string, enc []byte) error
	AuthenticateWithDid(did string, nonce string, signature []byte) (*model.AuthToken, error)
	CreateDidAuthenticationChallenge(did string) (*DidAuthenticationChallenge, error)
	CreateDidRegistrationChallenge(auth_token string) (*DidRegistrationChallenge, StreamClient, error)
}

func NewAuthClient(address string) (AuthClient, error) {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}
	client := AuthApi.NewAuthApiServiceClient(conn)
	return &authClient{
		conn:   conn,
		client: client,
	}, nil
}

func NewAuthStream(s grpc.ClientStream) StreamClient {
	return &streamClient{stream: s}
}

func (r *authClient) Close() {
	defer r.conn.Close()
}

func (r *authClient) AuthenticateWithPassword(email string, password string) (*model.AuthToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthnWithPasswordRequest{
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

func (r *authClient) CreateDidRegistrationChallenge(auth_token string) (*DidRegistrationChallenge, StreamClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthnWithDidRegisterStartRequest{}
	respClient, err := r.client.AuthnWithDidRegisterStart(ctx, req)

	if err != nil {
		return &DidRegistrationChallenge{}, NewAuthStream(respClient), err
	}

	resp, err := respClient.Recv()
	if err != nil {
		return &DidRegistrationChallenge{}, NewAuthStream(respClient), err
	}

	return &DidRegistrationChallenge{Nonce: resp.GetNonce()}, NewAuthStream(respClient), nil
}

func (r *authClient) AuthnWithDidRegister(did string, nonce string, enc []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthnWithDidRegisterRequest{
		Did:       did,
		Nonce:     nonce,
		Signature: enc,
	}

	_, err := r.client.AuthnWithDidRegister(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

func (r *authClient) CreateDidAuthenticationChallenge(did string) (*DidAuthenticationChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.CreateDidAuthenticationChallengeRequest{Did: did}
	resp, err := r.client.CreateDidAuthenticationChallenge(ctx, req)
	if err != nil {
		return &DidAuthenticationChallenge{}, err
	}

	return &DidAuthenticationChallenge{Nonce: resp.Nonce}, nil
}

func (r *authClient) AuthenticateWithDid(did string, nonce string, enc []byte) (*model.AuthToken, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthenticateWithDidRequest{
		Did:       did,
		Nonce:     nonce,
		Signature: enc,
	}

	res, err := r.client.AuthenticateWithDid(ctx, req)
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
