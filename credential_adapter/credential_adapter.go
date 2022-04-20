package credential_adapter

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"time"

	"github.com/knox-networks/knox-go/model"
	AdapterApi "go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	CREDENTIAL_ADAPTER_ADDRESS = "vc.knoxnetworks.io:5051"
	DEFAULT_ALIAS_LENGTH       = 5
)

type credentialAdapterClient struct {
	client AdapterApi.AdapterServiceClient
	conn   *grpc.ClientConn
}

type IssuanceChallenge struct {
	Nonce    string
	CredType string
	Url      string
}

type PresentationChallenge struct {
	Nonce string
	Url   string
}

type VerifiableCredential struct {
	Alias string
	Type  string
	Doc   []byte
}

type CredentialAdapterClient interface {
	Close() error
	CreateIssuanceChallenge(cred_type string, did string) (IssuanceChallenge, error)
	CreatePresentationChallenge() (*PresentationChallenge, error)
	IssueVerifiableCredential(cred_type string, did string, nonce string, signature []byte) (VerifiableCredential, error)
	PresentVerifiableCredential(creds []model.VerifiableCredential, proof model.Proof) error
}

func NewCredentialAdapterClient() (CredentialAdapterClient, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	conn, err := grpc.Dial(CREDENTIAL_ADAPTER_ADDRESS, opts...)

	if err != nil {
		return nil, err
	}
	client := AdapterApi.NewAdapterServiceClient(conn)

	return &credentialAdapterClient{
		client: client,
		conn:   conn,
	}, nil
}

func (c *credentialAdapterClient) Close() error {
	return c.conn.Close()
}

func (c *credentialAdapterClient) CreateIssuanceChallenge(cred_type string, did string) (IssuanceChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

func (c *credentialAdapterClient) CreatePresentationChallenge() (*PresentationChallenge, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.client.CreatePresentationChallenge(ctx, &AdapterApi.CreatePresentationChallengeRequest{
		CredentialType: AdapterApi.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED,
	})

	if err != nil {
		return &PresentationChallenge{}, err
	}

	return &PresentationChallenge{Url: resp.Endpoint, Nonce: resp.Nonce}, nil
}

func (c *credentialAdapterClient) IssueVerifiableCredential(cred_type string, did string, nonce string, signature []byte) (VerifiableCredential, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.client.IssueVerifiableCredential(ctx, &AdapterApi.IssueVerifiableCredentialRequest{
		CredentialType: getCredentialEnumFromName(cred_type),
		Did:            did,
		Signature:      signature,
		Nonce:          nonce,
	})

	if err != nil {
		return VerifiableCredential{}, err
	}

	doc, err := protojson.Marshal(resp.Credential)
	if err != nil {
		return VerifiableCredential{}, err
	}
	return VerifiableCredential{Doc: doc, Alias: CreateDefaultAlias(), Type: cred_type}, nil
}

func (c *credentialAdapterClient) PresentVerifiableCredential(creds []model.VerifiableCredential, proof model.Proof) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var converted_creds = make([]*AdapterApi.VerifiableCredential, len(creds))

	for i, cred := range creds {

		converted_creds[i] = &AdapterApi.VerifiableCredential{
			Context: cred.Context,
		}

	}

	_, err := c.client.PresentVerifiableCredential(ctx, &AdapterApi.PresentVerifiableCredentialRequest{
		Presentation: &AdapterApi.VerifiablePresentation{
			VerifiableCredential: converted_creds,
		},
	})

	if err != nil {
		return err
	}

	return nil
}

const PermanentResidentCard = "PermanentResidentCard"
const BankCard = "BankCard"

func getCredentialEnumFromName(credType string) AdapterApi.CredentialType {
	switch credType {
	case PermanentResidentCard:
		return AdapterApi.CredentialType_CREDENTIAL_TYPE_PERMANENT_RESIDENT_CARD
	case BankCard:
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
