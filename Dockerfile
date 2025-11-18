FROM --platform=$BUILDPLATFORM golang:1.24.1-bookworm AS builder-basis
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app/birdconfgen

COPY go.mod go.mod
# COPY go.sum go.sum


# RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go mod download

FROM --platform=$BUILDPLATFORM golang:1.24.1-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH

# COPY --from=builder-basis /go/pkg /go/pkg

WORKDIR /app/birdconfgen

COPY . .

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o bin/birdconfgen ./main.go

ENTRYPOINT ["/app/birdconfgen/bin/birdconfgen"]

FROM debian:bookworm

COPY --from=builder /app/birdconfgen/bin/birdconfgen /usr/local/bin/birdconfgen

ENTRYPOINT ["/usr/local/bin/birdconfgen"]
