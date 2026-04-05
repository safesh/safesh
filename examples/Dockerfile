# Stage 1: build safesh from source
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /safesh ./cmd/safesh

# Stage 2: test runner
FROM alpine:3.20
RUN apk add --no-cache bash curl
COPY --from=builder /safesh /usr/local/bin/safesh
