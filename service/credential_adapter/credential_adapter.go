package credential_adapter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/knox-networks/knox-go/helpers/slices"
	"github.com/knox-networks/knox-go/model"
	AdapterApi "go.buf.build/grpc/go/knox-networks/credential-adapter/vc_api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var (
	DEFAULT_ALIAS_LENGTH = 5
)

type credentialAdapterClient struct {
	client AdapterApi.CredentialAdapterServiceClient
	conn   *grpc.ClientConn
}

type IssuanceChallenge struct {
	Nonce    string
	CredType string
	Url      string
}

type PresentationChallenge struct {
	Nonce           string
	Url             string
	CredentialTypes []string
}

type VerifiableCredential struct {
	Alias string
	Type  string
	Doc   []byte
}

type CredentialAdapterClient interface {
	Close() error
	CreateIssuanceChallenge(cred_type string, did string, auth_token string) (IssuanceChallenge, error)
	CreatePresentationChallenge(credTypes []string) (*PresentationChallenge, error)
	IssueVerifiableCredential(cred_type string, did string, nonce string, signature []byte, auth_token string) (VerifiableCredential, error)
	PresentVerifiableCredential(vp map[string]interface{}, did string, nonce string, signature []byte) error
}

func NewCredentialAdapterClient(address string) (CredentialAdapterClient, error) {
	config := &tls.Config{}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(config))}

	conn, err := grpc.Dial(address, opts...)

	if err != nil {
		return nil, err
	}
	client := AdapterApi.NewCredentialAdapterServiceClient(conn)

	return &credentialAdapterClient{
		client: client,
		conn:   conn,
	}, nil
}

func (c *credentialAdapterClient) Close() error {
	return c.conn.Close()
}

func (c *credentialAdapterClient) CreateIssuanceChallenge(cred_type string, did string, auth_token string) (IssuanceChallenge, error) {
	md := metadata.New(map[string]string{"Authorization": "Bearer " + auth_token})
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 5*time.Second)

	defer cancel()
	resp, err := c.client.CreateIssuanceChallenge(ctx, &AdapterApi.CreateIssuanceChallengeRequest{
		CredentialType: getCredentialEnumFromName(cred_type),
		Did:            did,
	})

	if err != nil {
		return IssuanceChallenge{}, err
	}

	return IssuanceChallenge{Url: resp.Endpoint, CredType: cred_type, Nonce: resp.Nonce}, nil
}

func (c *credentialAdapterClient) CreatePresentationChallenge(credTypes []string) (*PresentationChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()
	resp, err := c.client.CreatePresentationChallenge(ctx, &AdapterApi.CreatePresentationChallengeRequest{
		CredentialTypes: slices.Map(credTypes, func(credType string) AdapterApi.CredentialType {
			return getCredentialEnumFromName(credType)
		}),
	})

	if err != nil {
		return &PresentationChallenge{}, err
	}

	return &PresentationChallenge{Url: resp.Endpoint, Nonce: resp.Nonce, CredentialTypes: credTypes}, nil
}

func (c *credentialAdapterClient) IssueVerifiableCredential(cred_type string, did string, nonce string, signature []byte, auth_token string) (VerifiableCredential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.client.IssueVerifiableCredential(ctx, &AdapterApi.IssueVerifiableCredentialRequest{
		CredentialType: getCredentialEnumFromName(cred_type),
		Did:            did,
		Signature:      signature,
		Nonce:          nonce,
	})

	println("About to check network error")

	if err != nil {
		return VerifiableCredential{}, err
	}

	return VerifiableCredential{Doc: []byte(resp.Credential), Alias: CreateDefaultAlias(), Type: cred_type}, nil
}

func (c *credentialAdapterClient) PresentVerifiableCredential(vp map[string]interface{}, did string, nonce string, signature []byte) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	encodedVp, err := json.Marshal(vp)
	if err != nil {
		return err
	}

	_, err = c.client.PresentVerifiableCredential(ctx, &AdapterApi.PresentVerifiableCredentialRequest{
		Presentation:   string(encodedVp),
		Nonce:          "",
		Signature:      []byte(""),
		Did:            "",
		CredentialType: []AdapterApi.CredentialType{},
	})

	if err != nil {
		return err
	}

	return nil
}

func getCredentialEnumFromName(credType string) AdapterApi.CredentialType {
	switch credType {
	case model.PermanentResidentCard:
		return AdapterApi.CredentialType_CREDENTIAL_TYPE_PERMANENT_RESIDENT_CARD
	case model.BankCard:
		return AdapterApi.CredentialType_CREDENTIAL_TYPE_BANK_CARD
	default:
		return AdapterApi.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED
	}
}

func CreateDefaultAlias() string {
	b := make([]byte, DEFAULT_ALIAS_LENGTH)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err.Error()) // rand should never fail
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}
