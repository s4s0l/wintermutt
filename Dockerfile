# Stage 1: Builder
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o wintermutt ./wintermutt

# Stage 2: Runtime
FROM alpine:3.20
WORKDIR /app
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 appuser
COPY --from=builder /build/wintermutt /app/wintermutt
USER appuser
ENTRYPOINT ["/app/wintermutt"]