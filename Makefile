BINARY  := sshvault
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.7.7)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build app install-app site test vet fmt run clean cross

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sshvault

app: build
	SSHVAULT_BIN="$(CURDIR)/$(BINARY)" \
	SSHVAULT_APP="$(CURDIR)/build/SSHVault.app" \
	SSHVAULT_VERSION="$(VERSION)" \
	./packaging/macos/build-app.sh

install-app: app
	mkdir -p "$(HOME)/Applications"
	rm -rf "$(HOME)/Applications/SSHVault.app"
	ditto "$(CURDIR)/build/SSHVault.app" "$(HOME)/Applications/SSHVault.app"

site:
	./packaging/pages/build.sh

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

run:
	go run ./cmd/sshvault

clean:
	rm -f $(BINARY) $(BINARY)-*
	rm -rf build

cross:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./cmd/sshvault
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 ./cmd/sshvault
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64  ./cmd/sshvault
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64  ./cmd/sshvault
