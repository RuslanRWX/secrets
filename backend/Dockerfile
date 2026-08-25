# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build

ARG VERSION=dev

WORKDIR /src

# Dependencies are copied first so the module cache survives source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/server ./cmd/server

# The final image carries the binary, the CA bundle for TLS connections to
# PostgreSQL, and nothing else.
FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server

# 65532 is the conventional "nonroot" uid; the Helm chart pins the same value.
USER 65532:65532

EXPOSE 8080

ENV PORT=8080

ENTRYPOINT ["/server"]
