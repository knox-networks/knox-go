package registry_client

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
