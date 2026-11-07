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

# Installs the binary and the provisional systemd unit. Palugada owns the
# final hardened unit, sudoers drop-in and env file in L4.
install-systemd: install
	install -Dm0644 deploy/lander.service $(UNIT_DIR)/lander.service
	systemctl daemon-reload
	systemctl enable --now lander
