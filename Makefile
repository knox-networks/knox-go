.PHONY: run build test mockgen
CHECK_FILES?=$$(go list ./... | grep -v /vendor/)

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ==============================================================================
# Main

build:   ## build the project
	go build

docker-build:
	docker build -t knox-go:latest -f ./etc/docker/Dockerfile.test .

test:   ## run tests
	go test -cover ./...

docker-test:
	chmod +x ./etc/docker/run_test.sh
	./etc/docker/run_test.sh

# ==============================================================================
# Tools commands

lint:  ## run linter
	echo "Starting linters"
	golangci-lint run ./...

mockgen: ## generate mock go files
	mockgen -destination=./service/credential_adapter/mock/mock_credential_adapter.go -package=mock -source=./service/credential_adapter/credential_adapter.go
	mockgen -destination=./mock/mock_knox.go -package=mock -source=knox.go
	mockgen -destination=./signer/mock/mock_signer.go -package=mock -source=signer/signer.go
	mockgen -build_flags=--mod=mod -destination=./service/credential_adapter/grpc_mock/mock_grpc_credential_client.go -package=grpc_mock "go.buf.build/grpc/go/knox-networks/credential-adapter/adapter_api/v1" AdapterServiceClient