.PHONY: run build test mockgen
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==============================================================================
# Main

build:   ## build the project
	@make deps-tidy
	go build

test:   ## run tests
	go test -cover ./...

update-knox-org-deps:
	go clean -modcache && go get -u ./... && go mod tidy
	GOPRIVATE=buf.build/* GOPROXY=https://buf.build,https://proxy.golang.org,direct go get buf.build/gen/go/knox-networks/user-mgmt/grpc/go
	GOPRIVATE=buf.build/* GOPROXY=https://buf.build,https://proxy.golang.org,direct go get buf.build/gen/go/knox-networks/credential-adapter/grpc/go
	GOPRIVATE=buf.build/* GOPROXY=https://buf.build,https://proxy.golang.org,direct go get buf.build/gen/go/knox-networks/registry-mgmt/grpc/go
# ==============================================================================
# Tools commands

lint:  ## run linter
	echo "Starting linters"
	golangci-lint run ./...

mockgen: ## generate mock go files
	mockgen -destination=./service/credential_adapter/mock/mock_credential_adapter.go -package=mock -source=./service/credential_adapter/credential_adapter.go
	mockgen -destination=./service/user_client/mock/mock_user_client.go -package=mock -source=./service/user_client/user_client.go
	mockgen -destination=./service/registry_client/mock/mock_registry_client.go -package=mock -source=./service/registry_client/registry_client.go
	mockgen -destination=./credential/mock/mock_credential.go -package=mock -source=./credential/credential.go
	mockgen -destination=./identity/mock/mock_identity.go -package=mock -source=./identity/identity.go
	mockgen -destination=./presentation/mock/mock_presentation.go -package=mock -source=./presentation/presentation.go
	mockgen -destination=./signer/mock/mock_signer.go -package=mock -source=signer/signer.go
	mockgen -destination=./helpers/crypto/mock/mock_crypto.go -package=mock -source=helpers/crypto/crypto.go
	mockgen -build_flags=--mod=mod -destination=./service/credential_adapter/grpc_mock/mock_grpc_credential_client.go -package=grpc_mock "buf.build/gen/go/knox-networks/credential-adapter/grpc/go/vc_api/v1/vc_apiv1grpc" CredentialAdapterServiceClient
	mockgen -build_flags=--mod=mod -destination=./service/user_client/grpc_mock/mock_grpc_user_client.go -package=grpc_mock "buf.build/gen/go/knox-networks/user-mgmt/grpc/go/user_api/v1/user_apiv1grpc" UserApiService_CreateRegisterWalletChallengeClient,UserApiServiceClient,UserApiService_CreateAuthnBrowserWithWalletChallengeClient

deps-tidy:   ## tidy up dependencies and update vendor folder
	@make update-knox-org-deps && make mockgen
	go mod tidy
	go mod vendor