---
title: Architecture
description: The guard, the resolver, and the policy
weight: 5
---

# Architecture

Three small pieces, wired through contracts so every part is swappable and testable.

```
UrlGuard (contract)  ←impl─  Guard
   ├─ GuardPolicy   (immutable policy, built from config)
   └─ Resolver (contract)  ←impl─  SystemResolver / FakeResolver
```

## `UrlGuard` (contract) → `Guard`

The one capability: decide whether a URL is safe and produce pinned connection
options. `Guard` is stateless; it composes a `GuardPolicy` and a `Resolver`.

- `assertSafe()` / `isSafe()` — validate for a **server-side fetch** (resolves DNS).
- `assertSafeRedirect()` — validate a **browser redirect target** (no DNS; the
  browser resolves at click time), still blocking IP literals and blocked hosts.
- `pinnedOptions()` — Guzzle options that pin the connection (`CURLOPT_RESOLVE`),
  add a post-connection IP check (`on_stats`), and disable redirects.

## `GuardPolicy`

An immutable value object holding the normalized policy (allowed schemes, blocked
hosts/suffixes/IPs/CIDRs, `enforce`, `pin_dns`). Built once from `config/ssrf.php`
via `GuardPolicy::fromConfig()` and bound as a singleton.

## `Resolver` (contract) → `SystemResolver`

Hostname → IP addresses. `SystemResolver` consults system DNS for **both A and
AAAA** records. Abstracting resolution is what makes the guard testable (bind a
`FakeResolver`) and lets a deployment supply a pinned/internal DNS view.

## The validation pipeline

1. Parse the URL; require a scheme + host.
2. Reject a disallowed scheme and any embedded credentials.
3. Normalize the host (lowercase, strip brackets/trailing dot); reject blocked
   names/suffixes.
4. Resolve to IPs (or normalize an IP literal in redirect mode).
5. For **every** address: reject blocked IPs and blocked CIDRs, then extract and
   re-check any IPv4 embedded in an IPv6 transition form.
6. Produce pinned options for the caller's HTTP client.

## Why validate the resolved IP, not the URL string

Attackers obfuscate hosts a dozen ways — decimal/hex/octal IP literals, IPv6
transition forms, unicode dots, trailing dots. Validating the **resolved address**
rather than the textual host neutralizes that entire class in one move, because the
resolver and the checks agree on a canonical address.
