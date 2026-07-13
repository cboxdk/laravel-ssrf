# Security Policy

`cboxdk/laravel-ssrf` is itself a security control, so a flaw here is high impact.

## Reporting a vulnerability

**Do not open a public issue.** Report privately via
[GitHub Private Vulnerability Reporting](https://github.com/cboxdk/laravel-ssrf/security/advisories/new)
(repository → **Security** → **Report a vulnerability**). This is a pre-1.0,
best-effort open-source project; we'll respond as promptly as we can and coordinate
disclosure with you. Good-faith research under this policy is authorized (safe harbor).

If you have found an SSRF **bypass** — a URL that the guard accepts but which
resolves to a private, reserved, or metadata address — that is exactly the class of
report we most want to see. Please include the URL, the address it reaches, and the
environment (IPv4/IPv6, proxy in path, resolver).

## Scope reminder

This is an application-layer guard: **defense in depth, not a complete fix.** A
network egress allow-list is the only thing that fully closes SSRF, and an HTTP
proxy in the request path defeats connection pinning. See the "Honest scope"
section of the [README](README.md).

## Supported versions

Security fixes target the latest release. During `0.x`, only the latest tag.
