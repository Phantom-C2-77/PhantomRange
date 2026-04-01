# ── Build stage ──
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /phantomshop ./cmd/server/

# ── Runtime stage ──
FROM alpine:3.19
RUN adduser -D -h /app phantomshop
WORKDIR /app
COPY --from=builder /phantomshop .
COPY internal/shop/static/ internal/shop/static/
RUN mkdir -p data && chown -R phantomshop:phantomshop /app
USER phantomshop
EXPOSE 9000
ENTRYPOINT ["./phantomshop"]
CMD ["-addr", ":9000"]
