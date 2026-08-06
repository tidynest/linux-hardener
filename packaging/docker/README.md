# Docker image

Minimal `FROM scratch` image carrying only the static musl `hardener` binary,
for read-only scans and compliance reports against the host.

Build from the **repository root** (the build context must be the repository
root, where `.dockerignore` lives):

```bash
docker build -f packaging/docker/Dockerfile -t linux-hardener .
```

Usage, mount flags, and the capability boundary (what degrades in-container,
why `apply` is unsupported) are documented in the
[Docker section of the installation guide](../../docs/guide/installation.md#run-with-docker-scan-and-report-only).
