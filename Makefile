BINARY  := sshvault
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.7.4)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt run clean cross

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sshvault

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

cross:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-arm64 ./cmd/sshvault
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-darwin-amd64 ./cmd/sshvault
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-arm64  ./cmd/sshvault
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY)-linux-amd64  ./cmd/sshvault
