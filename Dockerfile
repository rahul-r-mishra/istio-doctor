FROM golang:1.26-alpine AS builder

WORKDIR /build

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /bin/istio-doctor .

# ────────────────────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates kubectl

COPY --from=builder /bin/istio-doctor /usr/local/bin/istio-doctor

# Run as non-root
RUN addgroup -S istio-doctor && adduser -S -G istio-doctor istio-doctor
USER istio-doctor

ENTRYPOINT ["istio-doctor"]
CMD ["summary"]
