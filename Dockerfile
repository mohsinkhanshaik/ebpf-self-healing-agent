FROM golang:1.22-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go mod tidy && make generate build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl
COPY --from=build /src/bin/healerd /usr/local/bin/healerd
ENTRYPOINT ["/usr/local/bin/healerd"]
