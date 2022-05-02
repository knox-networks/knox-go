package auth_client

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/credentials/insecure"

	AuthApi "go.buf.build/grpc/go/knox-networks/auth-mgmt/auth_api/v1"

	"google.golang.org/grpc"
)

type authClient struct {
	client AuthApi.AuthApiServiceClient
	conn   *grpc.ClientConn
}

type streamClient struct {
	stream AuthApi.AuthApiService_AuthnWithDidRegisterStartClient
}

type StreamClient interface {
	WaitForCompletion() error
	Close() error
}

type DidRegistrationChallenge struct {
	Nonce string
}

type AuthClient interface {
	Close()
	AuthnWithDid(did string, nonce string, enc []byte) error
	AuthnWithDidRegister(did string, nonce string, enc []byte) error
	AuthnWithDidStart() (AuthApi.AuthApiService_AuthnWithDidStartClient, error)
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

func NewAuthStream(s AuthApi.AuthApiService_AuthnWithDidRegisterStartClient) StreamClient {
	return &streamClient{stream: s}
}

func (r *authClient) Close() {
	defer r.conn.Close()
}

func (r *authClient) AuthnWithDid(did string, nonce string, enc []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthnWithDidRequest{
		Did:       did,
		Nonce:     nonce,
		Signature: enc,
	}

	_, err := r.client.AuthnWithDid(ctx, req)
	if err != nil {
		return err
	}

	return nil
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

func (r *authClient) AuthnWithDidStart() (AuthApi.AuthApiService_AuthnWithDidStartClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &AuthApi.AuthnWithDidStartRequest{}
	return r.client.AuthnWithDidStart(ctx, req)
}

func (s *streamClient) WaitForCompletion() error {
	res, err := s.stream.Recv()
	if err != nil {
		return err
	}

	if res.GetOk() != "" {
		return nil
	}

	return errors.New("unexpected error")
}

func (s *streamClient) Close() error {
	return s.stream.CloseSend()
}
