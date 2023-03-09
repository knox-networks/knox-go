.PHONY: run build test mockgen
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==============================================================================
# Main

build:   ## build the project
	@make deps-tidy
	go build

docker-build:
	docker build -t knox-go:latest -f ./etc/docker/Dockerfile .

test:   ## run tests
	go test -cover ./...

docker-test:
	chmod +x ./etc/docker/run_test.sh
	./etc/docker/run_test.sh

update-knox-org-deps:
	GOPRIVATE=go.buf.build/* GOPROXY=https://go.buf.build,https://proxy.golang.org,direct go get go.buf.build/grpc/go/knox-networks/user-mgmt
	GOPRIVATE=go.buf.build/* GOPROXY=https://go.buf.build,https://proxy.golang.org,direct go get go.buf.build/grpc/go/knox-networks/credential-adapter
	GOPRIVATE=go.buf.build/* GOPROXY=https://go.buf.build,https://proxy.golang.org,direct go get go.buf.build/grpc/go/knox-networks/registry-mgmt
# ==============================================================================
# Tools commands

lint:  ## run linter
	echo "Starting linters"
	golangci-lint run ./...

mockgen: ## generate mock go files
	@make update-knox-org-deps
	mockgen -destination=./service/credential_adapter/mock/mock_credential_adapter.go -package=mock -source=./service/credential_adapter/credential_adapter.go
	mockgen -destination=./service/user_client/mock/mock_user_client.go -package=mock -source=./service/user_client/user_client.go
	mockgen -destination=./service/registry_client/mock/mock_registry_client.go -package=mock -source=./service/registry_client/registry_client.go
	mockgen -destination=./credential/mock/mock_credential.go -package=mock -source=./credential/credential.go
	mockgen -destination=./identity/mock/mock_identity.go -package=mock -source=./identity/identity.go
	mockgen -destination=./presentation/mock/mock_presentation.go -package=mock -source=./presentation/presentation.go
	mockgen -destination=./signer/mock/mock_signer.go -package=mock -source=signer/signer.go
	mockgen -destination=./helpers/crypto/mock/mock_crypto.go -package=mock -source=helpers/crypto/crypto.go
	mockgen -build_flags=--mod=mod -destination=./service/credential_adapter/grpc_mock/mock_grpc_credential_client.go -package=grpc_mock "go.buf.build/grpc/go/knox-networks/credential-adapter/vc_api/v1" CredentialAdapterServiceClient
	mockgen -build_flags=--mod=mod -destination=./service/user_client/grpc_mock/mock_grpc_user_client.go -package=grpc_mock "go.buf.build/grpc/go/knox-networks/user-mgmt/user_api/v1" UserApiService_CreateRegisterWalletChallengeClient,UserApiServiceClient,UserApiService_CreateAuthnBrowserWithWalletChallengeClient

deps-tidy:   ## tidy up dependencies and update vendor folder
	@make update-knox-org-deps
	go mod tidy
	go mod vendor