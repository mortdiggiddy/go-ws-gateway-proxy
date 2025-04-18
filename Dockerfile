FROM golang:1.23-alpine AS builder

# Enable Go modules, set working directory
ENV CGO_ENABLED=0 \
    GO111MODULE=on

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the Go binary statically
RUN go build -o gateway ./cmd/main.go

FROM alpine:3.18

WORKDIR /app

COPY --from=builder /app/gateway .

EXPOSE 8080

ENTRYPOINT ["./gateway"]
