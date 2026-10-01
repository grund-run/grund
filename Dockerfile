# syntax=docker/dockerfile:1.7
#
# Builds grund from source, for `docker compose up` from a clone. CI does not
# use this file: it builds and tests the binary once and packages that one
# with Dockerfile.prebuilt. The final stages of the two files are identical
# but for where the files come from: here the build stage, there the build
# context CI's release step stages.
FROM rust:1.98.1-alpine3.24 AS build
# musl-dev: rust:*-alpine targets musl, so the binary is static and runs on
# scratch. protobuf-dev: protoc and the well-known types, for the API codegen.
# ca-certificates: the CA bundle the image ships, as in CI's release step.
RUN apk add --no-cache musl-dev protobuf-dev ca-certificates
WORKDIR /src
COPY . .
# The commit to report in /health/ready; "unknown" unless passed in.
ARG GRUND_REVISION=unknown
ENV GRUND_REVISION=${GRUND_REVISION}
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p grund && mkdir -p /out/var/lib/grund \
    && cp target/release/grund /out/grund && cp /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt

FROM scratch
COPY --from=build /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/var/lib/grund /var/lib/grund
COPY --from=build /out/grund /grund
USER 65532:65532
ENV GRUND_LISTEN=0.0.0.0:8080 \
    GRUND_LOG_FORMAT=json
EXPOSE 8080 443
ENTRYPOINT ["/grund"]
CMD ["serve"]
