# Docker Image

A minimal container image for running **read-only scans and compliance reports**
against the host. The image is built `FROM scratch` and contains a single file:
the statically linked musl `hardener` binary: no shell, no libraries, no
package manager.

## Build

From the repository root (the build context must be the repository root, where
`.dockerignore` lives):

```bash
docker build -f packaging/docker/Dockerfile -t linux-system-hardener .
```

`--build-arg BUILD_JOBS=<n>` caps rustc parallelism on thermally constrained
hosts; unset, the build uses all cores.

## Usage

```bash
# Read-only scan of the host's config surface:
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var/log:/var/log:ro -v /usr/lib:/usr/lib:ro \
  linux-system-hardener scan --format json
```

Compliance reports work the same way:

```bash
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var/log:/var/log:ro -v /usr/lib:/usr/lib:ro \
  linux-system-hardener report --framework cis
```

### Why these flags

- `--pid=host`: the container shares the host's PID namespace, so `/proc/sys`
  exposes the host's global sysctls (`kernel.*`, `fs.*`, `vm.*`) and the kernel
  plugin reads real values. Network sysctls (`net.*`) are read from the
  container's own network namespace; add `--network=host` if those checks
  should reflect the host's tuning rather than namespace defaults.
- `-v /etc:/etc:ro`: SSH, PAM, permissions and distro-detection checks read
  the host's real configuration and cannot write to it.
- `-v /var/log:/var/log:ro`: log-file permission checks.
- `-v /usr/lib:/usr/lib:ro`: vendor systemd unit and library permission
  checks.

Filesystem checks only evaluate paths visible inside the container; anything
outside the mounts is silently absent from the results. Widen coverage with
further read-only mounts, e.g. `-v /boot:/boot:ro -v /root:/root:ro` for the
permissions plugin's boot- and root-directory checks.

## Capability boundary

In a container the hardener can meaningfully run **scan and report, read-only,
against mounted host state**. `systemctl`/D-Bus-dependent checks (services and
parts of the audit/MAC/firewall plugins) degrade: they report tool-unavailable
findings rather than lying. For example, on a host with auditd running, the
in-container scan reports `audit_not_installed` because it cannot see the
host's service manager: treat such findings as *unverifiable in-container*,
not as host truth.

**`apply` is unsupported in a container by design.** Writing host state would
require `--privileged` plus host namespaces, which defeats the isolation that
justifies the container in the first place. Use a native install (package,
static binary or source, see [`docs/guide/installation.md`](../../docs/guide/installation.md)) to
apply hardening.

Remote (`--ssh`) operations are also unavailable: the image ships no `ssh`
client binary.

## Validation

The Docker section of
[`docs/reference/distribution-validation.md`](../../docs/reference/distribution-validation.md)
records exactly what has been validated with this image.
