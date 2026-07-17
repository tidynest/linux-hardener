# Build stage — static musl binary, same target the release tarball ships.
FROM rust:1.97-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# BUILD_JOBS caps rustc parallelism for thermally constrained hosts (empty = all cores).
ARG BUILD_JOBS=
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p hardener-cli ${BUILD_JOBS:+-j"$BUILD_JOBS"}

# Runtime — nothing but the binary.
FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/hardener /hardener
ENTRYPOINT ["/hardener"]
CMD ["--help"]
