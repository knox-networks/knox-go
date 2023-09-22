package registry_client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/knox-networks/knox-go/model"
	"time"

	"google.golang.org/grpc/credentials"

	RegistryGrpc "buf.build/gen/go/knox-networks/registry-mgmt/grpc/go/registry_api/v1/registry_apiv1grpc"
	RegistryApi "buf.build/gen/go/knox-networks/registry-mgmt/protocolbuffers/go/registry_api/v1"
	"google.golang.org/grpc"
)

type registryClient struct {
	client RegistryGrpc.RegistryServiceClient
	conn   *grpc.ClientConn
}

type RegistryClient interface {
	Create(did string, doc []byte) error
	Resolve(did string) (*model.DidDocument, error)
	Revoke(did, didDoc string) error
	Close()
}

func NewRegistryClient(address string) (RegistryClient, error) {
	var opts []grpc.DialOption
	tlsConfig := &tls.Config{}

	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		return nil, err
	}

	client := RegistryGrpc.NewRegistryServiceClient(conn)
	return &registryClient{
		conn:   conn,
		client: client,
	}, nil
}

func (r *registryClient) Close() {
	defer r.conn.Close()
}

func (r *registryClient) Create(did string, doc []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	docMap := make(map[string]interface{})
	err := json.Unmarshal(doc, &docMap)
	if err != nil {
		return err
	}

	req := &RegistryApi.CreateRequest{
		Did:      did,
		Document: string(doc),
	}
	_, err = r.client.Create(ctx, req)
	if err != nil {
		return err
	}
	return nil
}

func (r *registryClient) Resolve(did string) (*model.DidDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &RegistryApi.ResolveRequest{
		Did: did,
	}
	resp, err := r.client.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	protoDoc := resp.GetDidDocument()
	//convert to json
	jsonDidDoc, err := protoDoc.MarshalJSON()

	if err != nil {
		return nil, err
	}
	//We need to convert the json_did_doc to a compacted JSON-LD form (currently expanded)
	//Implement here

	didDoc := model.DidDocument{}
	err = json.Unmarshal(jsonDidDoc, &didDoc)
	if err != nil {
		return nil, err
	}

	return &didDoc, nil
}

func (r *registryClient) Revoke(did, didDoc string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &RegistryApi.RevokeRequest{
		Did:      did,
		Document: didDoc,
	}
	_, err := r.client.Revoke(ctx, req)
	if err != nil {
		return err
	}

	return nil
}
