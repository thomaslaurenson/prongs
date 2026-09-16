# Build stage - produces a static binary
FROM golang:1.27-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o prongs .

# Runtime stage - scratch image, just the binary
FROM scratch
COPY --from=builder /build/prongs /prongs
ENTRYPOINT ["/prongs"]
# Pass targets via -e TARGET_CIDRS=... at runtime, or override CMD entirely.
# e.g. docker run --rm -e TARGET_CIDRS=10.0.0.0/8 prongs scan --all
CMD ["scan", "--all"]
