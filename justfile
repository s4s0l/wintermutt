set shell := ["bash", "-c"]

build_dir := "build"
binary_name := "server"

build:
    mkdir -p {{build_dir}}
    go build -o {{build_dir}}/{{binary_name}} ./wintermutt

# Run the server ... (will not work)
run: build
    ./{{build_dir}}/{{binary_name}}

# Run tests
test:
    go test -v ./...

# Run tests with coverage and generate HTML report
test-coverage:
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

# Run go vet
lint:
    go vet ./...

# Format Go code
fmt:
    go fmt ./...

# Clean build artifacts
clean:
    rm -rf {{build_dir}} coverage.out coverage.html

# Run integration tests
test-itg:
    ./scripts/test-integration.sh

build-docker:
    docker build -t wintermutt:latest .
