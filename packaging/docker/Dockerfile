# Build stage - static musl binary, same target the release tarball ships.
FROM rust:1.97-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
# BUILD_JOBS caps rustc parallelism for thermally constrained hosts (empty = all cores).
ARG BUILD_JOBS=
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p hardener-cli ${BUILD_JOBS:+-j"$BUILD_JOBS"}

# Runtime - the binary and its licences. It embeds Noto Sans for PDF reports,
# and the font's SIL OFL 1.1 asks for its text in every copy.
FROM scratch
LABEL org.opencontainers.image.licenses="Apache-2.0 AND OFL-1.1"
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/hardener /hardener
COPY LICENSE crates/hardener-compliance/src/fonts/LICENSE-noto-sans.txt /usr/share/licenses/linux-hardener/
ENTRYPOINT ["/hardener"]
CMD ["--help"]
