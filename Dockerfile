FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/panbridge .

FROM alpine:3.22

WORKDIR /app

RUN addgroup -S panbridge && adduser -S -G panbridge panbridge

COPY --from=builder /out/panbridge /app/panbridge

ENV PORT=10199 \
    P2T_DB_PATH=/app/data/p2t.db \
    LOG_LEVEL=INFO

RUN mkdir -p /app/data && chown -R panbridge:panbridge /app

USER panbridge

EXPOSE 10199

VOLUME ["/app/data"]

ENTRYPOINT ["/app/panbridge"]
