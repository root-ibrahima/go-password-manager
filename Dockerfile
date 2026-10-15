FROM golang:1.27-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS builder

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -o /out/go-password-manager .

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

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
