# syntax=docker/dockerfile:1.7
#
# Builds grund from source, for `docker compose up` from a clone. CI does not
# use this file: it builds and tests the binary once and packages that one
# with Dockerfile.prebuilt. The runtime stages of the two files are identical.
FROM rust:1.98-alpine AS build
# musl-dev: rust:*-alpine targets musl, so the binary is static and runs on
# scratch. protobuf-dev: protoc and the well-known types, for the API codegen.
RUN apk add --no-cache musl-dev protobuf-dev
WORKDIR /src
COPY . .
# The commit to report in /health/ready; "unknown" unless passed in.
ARG GRUND_REVISION=unknown
ENV GRUND_REVISION=${GRUND_REVISION}
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p grund && cp target/release/grund /grund

FROM alpine:3.22 AS runtime-files
RUN apk add --no-cache ca-certificates && mkdir -p /out/var/lib/grund

FROM scratch
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=65532:65532 /out/var/lib/grund /var/lib/grund
COPY --from=build /grund /grund
USER 65532:65532
ENV GRUND_LISTEN=0.0.0.0:8080 \
    GRUND_LOG_FORMAT=json
EXPOSE 8080
ENTRYPOINT ["/grund"]
CMD ["serve"]
