# Upgrading

**Last Updated**: 2026-08-01

Some releases fixed defects that a hardened host keeps carrying after the
upgrade. Installing a newer version repairs the tool, not the system it already
changed, so each notice below tells you how to check whether your host is
affected and what to do about it.

Read the section for the version you are upgrading **from**. If you are
installing for the first time, none of this applies to you.

The full per-release history is in [CHANGELOG.md](../../CHANGELOG.md).

---

## Contents

- [1.4.0 and earlier: rollback could delete account files on a remote host](#140-and-earlier-rollback-could-delete-account-files-on-a-remote-host)
- [1.4.0 and earlier: password ageing was never actually written](#140-and-earlier-password-ageing-was-never-actually-written)
- [1.5.0 and earlier: openSUSE hosts may have a short file masking the vendor copy](#150-and-earlier-opensuse-hosts-may-have-a-short-file-masking-the-vendor-copy)
- [1.5.0 and earlier: compliance reports could pass controls that were never assessed](#150-and-earlier-compliance-reports-could-pass-controls-that-were-never-assessed)
- [1.5.0 and earlier: rollback did not restore systemd unit files](#150-and-earlier-rollback-did-not-restore-systemd-unit-files)

---

## 1.4.0 and earlier: rollback could delete account files on a remote host

**Affects** anyone who managed remote hosts over SSH. Local-only use was never
affected.

`hardener rollback` could delete account files on the remote host. Do not run it
on 1.4.0 or earlier against a remote target; upgrade first.

Fixed in **1.5.0**. Full detail:
[GHSA-x4xp-32mf-xwjh](https://github.com/tidynest/linux-system-hardener/security/advisories/GHSA-x4xp-32mf-xwjh).

---

## 1.4.0 and earlier: password ageing was never actually written

**Affects** every host hardened with the PAM plugin on 1.4.0 or earlier.

Those releases wrote `/etc/login.defs` in a syntax the file does not accept, so
`PASS_MAX_DAYS`, `PASS_MIN_DAYS` and `PASS_WARN_AGE` were left unchanged. A
later scan then read the tool's own discarded line back and reported the host as
compliant, so nothing pointed at the problem.

Fixed in **1.5.0**, in both the writing and the reading, and the fix is verified
against the system rather than against the tool.

### Repairing a host

Upgrading does not repair a host that was already hardened, because the old file
is still on disk. Re-apply:

```bash
sudo hardener apply -p pam-hardening
```

### Confirming it

Ask the system rather than the tool. `/etc/login.defs` supplies defaults for new
accounts only, so create a throwaway account and read what it was given:

```bash
sudo useradd --no-create-home ageing-probe
sudo chage -l ageing-probe | grep -i maximum
sudo userdel ageing-probe
```

A large number such as 99999 means the ageing policy is not in force. After
re-applying on 1.5.0 or later it should read 90.

---

## 1.5.0 and earlier: openSUSE hosts may have a short file masking the vendor copy

**Affects** openSUSE hosts hardened on 1.5.0 or earlier. Other distributions
were never affected.

openSUSE keeps packaged configuration under `/usr/etc` and reserves `/etc` for
your overrides, and an `/etc` file overrides the vendor copy **as a whole file**
rather than setting by setting. Every release up to and including 1.5.0 created
a three-line `/etc/login.defs`, which silenced the roughly 35 other settings the
vendor file makes. `ENCRYPT_METHOD` was among them, and it chooses the hashing
algorithm for every password set afterwards: masking a vendor `ENCRYPT_METHOD
SHA512` drops password hashing to DES, which truncates every password at eight
characters.

`/etc/security/faillock.conf` and `/etc/security/pwhistory.conf` were affected
the same way.

### Checking

Look for a file of a few lines where `/usr/etc` holds a long one:

```bash
wc -l /etc/login.defs /etc/security/faillock.conf /etc/security/pwhistory.conf
```

### Repairing

Restore the vendor file, then re-apply your intended values:

```bash
sudo cp /usr/etc/login.defs /etc/login.defs
```

The tool cannot repair this for you, because an `/etc` file that already exists
is edited rather than replaced. Since 1.5.1 the scan raises a Medium finding
naming the keys your `/etc` file masks, which is what points an affected
operator at this page.

### What each version does

| version | behaviour on openSUSE |
|---|---|
| up to 1.5.0 | creates a short `/etc` file, masking the vendor copy. **This is the defect.** |
| 1.5.1 | refuses the write, so nothing is masked and PAM hardening is declined instead |
| current `main` | creates the `/etc` copy **from the vendor file** and edits the managed directives into it, so the host is hardened and the vendor settings survive |

If you are running 1.5.1 and your openSUSE host reports PAM hardening as
declined, that is the release behaving as designed rather than a fault.

---

## 1.5.0 and earlier: compliance reports could pass controls that were never assessed

**Affects** any compliance report generated on 1.5.0 or earlier, and desktop
users much more than command-line users.

A compliance report decides `Pass` from what a plugin declares it covers plus
the absence of a finding. Up to and including 1.5.0, a plugin that produced no
evidence therefore passed every control it covers, on the silence its own
absence caused.

From the command line this needed a plugin's scan to fail. **In the desktop it
needed no failure at all**: disabling a plugin, or scanning a subset, was enough
for every control of every plugin that did not run to be reported as satisfied.

Any report you have kept, filed or forwarded may therefore state passes that
were never assessed.

### Repairing

Regenerate. Desktop users should do so unconditionally:

```bash
sudo hardener report --framework cis
```

Fixed in **1.5.1**: a plugin that contributed no evidence now reports its
controls as **Manual Review**.

---

## 1.5.0 and earlier: rollback did not restore systemd unit files

**Affects** hosts where the services plugin disabled something.

The services plugin recorded unit files in its checkpoint, but the rollback
allow-list did not cover the systemd unit directories, so `hardener rollback`
aborted without restoring anything. Nothing was lost or damaged.

### Repairing

Re-enable by hand:

```bash
sudo systemctl enable --now <service>
```

Fixed in **1.5.1**.

---

## A note from the author

This is a tool you install to make a system safer, and in the cases above it did
the opposite. If any of it has cost you anything, I apologise. Known problems
are listed here as they are found, including the ones not yet fixed, so you can
judge the risk yourself.
