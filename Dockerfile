FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -o /out/go-password-manager .

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher0 \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /usr/sbin/nologin appuser

WORKDIR /app
COPY --from=builder /out/go-password-manager .
COPY --from=builder /src/web/templates ./web/templates
COPY --from=builder /src/web/static ./web/static
RUN chown -R appuser:appuser /app

USER appuser

VOLUME ["/app"]
EXPOSE 8080

# S'applique au mode par défaut (serveur web). Sans objet pour un `docker run
# <image> add|list|get|menu` en mode CLI ponctuel.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

ENTRYPOINT ["./go-password-manager"]
CMD ["web"]
