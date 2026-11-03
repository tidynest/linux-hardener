# Docker image

Minimal `FROM scratch` image carrying the static musl `hardener` binary and
its two licence texts, for read-only scans and compliance reports against the
host. The binary embeds Noto Sans for PDF reports, so the image ships that
font's licence beside `LICENSE`, and its `org.opencontainers.image.licenses`
label reads `Apache-2.0 AND OFL-1.1`.

Build from the **repository root** (the build context must be the repository
root, where `.dockerignore` lives):

```bash
docker build -f packaging/docker/Dockerfile -t linux-hardener .
```

Usage, mount flags, and the capability boundary (what degrades in-container,
why `apply` is unsupported) are documented in the
[Docker section of the installation guide](../../docs/guide/installation.md#run-with-docker-scan-and-report-only).
