# session-broker image. Build context is `repo/`.
#
#   docker build -t session-broker .
#
# `mock-idp` is deliberately not built into the image (see release.yml).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p session-broker

# distroless/cc: glibc + libgcc, no shell, no package manager. Everything else
# is statically linked (SQLite is `bundled`, TLS is rustls).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/session-broker /usr/local/bin/session-broker
# The state directory must be a volume and must be writable by uid 65532: it
# holds the SQLite store AND the custody keyfile. Losing either is a forced
# org-wide re-login; back both up together.
COPY --from=build --chown=65532:65532 /tmp /data
VOLUME /data

ENV BROKER_BIND_ADDR=0.0.0.0:8080 \
    BROKER_INTERNAL_BIND_ADDR=0.0.0.0:8090 \
    BROKER_DB_PATH=/data/session-broker.db \
    BROKER_KEYFILE_PATH=/data/session-broker.key \
    BROKER_LOG_FORMAT=json

# 8080 is the public lane; 8090 is the internal/admin/metrics lane and must
# never be published beyond the platform network.
EXPOSE 8080 8090
USER nonroot:nonroot
# Probes (no shell in the image, so no HEALTHCHECK): liveness GET :8080/healthz,
# readiness GET :8090/readyz. SIGTERM drains; give the pod a grace period of at
# least BROKER_SHUTDOWN_GRACE_SECS + 5.
ENTRYPOINT ["/usr/local/bin/session-broker"]
