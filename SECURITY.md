# Security Policy

ejson protects secrets, so security reports are taken seriously and handled
ahead of other work.

## Supported versions

Security fixes are made on `main` and released as a new patch or minor
version. Only the latest release is supported; please upgrade before
reporting.

| Version          | Supported |
| ---------------- | --------- |
| latest `2.x`     | ✅        |
| older releases   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report it privately through GitHub instead:
[**Report a vulnerability**](https://github.com/runlevel5/ejson-rs/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Please include:

- the ejson version (`ejson --version`) and platform;
- the scheme involved (`v1`, `v2`) and file format, if relevant;
- steps or a minimal file to reproduce, and what an attacker gains.

Never include real private keys or secrets in a report. Generate a throwaway
keypair with `ejson keygen` for any reproduction.

## What to expect

- An acknowledgement within a few days.
- An assessment, and a fix or mitigation plan, as soon as the issue is
  understood.
- A GitHub security advisory (and a RustSec advisory where appropriate) when
  the fix is released. Reporters are credited unless they prefer otherwise.

## Scope

In scope: anything that lets someone read secrets they shouldn't, tamper with
encrypted values or keys undetected, or run code via ejson. That includes the
CLI, the `ejson` library crate, the wire format, and the release and packaging
pipeline (GitHub Releases, Homebrew formula, crates.io).

Out of scope: attacks that already require reading the private key file or the
memory of a running `ejson` process, and weaknesses in the user's own key
storage.
