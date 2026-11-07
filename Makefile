BINARY      := lander
CMD         := ./cmd/lander
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOFLAGS     ?=
UNIT_DIR    ?= /etc/systemd/system
BIN_DIR     ?= /usr/local/bin

.PHONY: all build test vet lint fmt clean install install-systemd

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(CMD)

test:
	go test -race -count=1 -coverprofile=coverage.out ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -rf bin coverage.out

install: build
	install -Dm0755 bin/$(BINARY) $(BIN_DIR)/$(BINARY)

# Installs binary, hardened unit and (if absent) env file, then enables lander.
# Run as root on the VPS after orbit-suite/vps-bootstrap/bootstrap.sh.
# The service is started only when the env token has been changed.
install-systemd: install
	UNIT_DIR='$(UNIT_DIR)' sh deploy/install-systemd.sh
