ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
  TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
  TARGET_ARCH := arm64
else
  TARGET_ARCH := $(ARCH)
endif
BPF_CFLAGS := -O2 -g -Wall -D__TARGET_ARCH_$(TARGET_ARCH) -I/usr/include/$(ARCH)-linux-gnu
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all deps generate build test vet demo smoke clean

all: generate build

deps:
	go mod tidy

# Compile bpf/agent.bpf.c and generate Go bindings (needs clang + libbpf headers).
generate:
	cd internal/probe && go run github.com/cilium/ebpf/cmd/bpf2go \
		-go-package probe -target bpfel -tags linux -no-strip \
		-type event -type conn_key \
		agent ../../bpf/agent.bpf.c -- $(BPF_CFLAGS)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/healerd ./cmd/healerd

test:
	go test -race ./...

vet:
	go vet ./...

# Replay a recorded incident through the engine. Works on any OS, no root.
demo:
	go run ./cmd/healerd -config examples/healerd.yaml -replay examples/incident.jsonl -dry-run

# Load and attach the real eBPF programs, then trigger signals. Needs root.
smoke: build
	sudo ./scripts/smoke.sh

clean:
	rm -rf bin internal/probe/agent_bpfel.go internal/probe/agent_bpfel.o
