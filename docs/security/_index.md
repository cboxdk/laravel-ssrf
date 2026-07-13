---
title: Security
description: Threat model, defended bypasses, and honest scope
weight: 8
---

# Security

## Threat model

An attacker controls, in whole or part, a URL the application fetches server-side
(a webhook endpoint, an import URL, an SSO callback). Their goal is to make the
server reach somewhere it shouldn't: the cloud metadata service (to steal instance
credentials), an internal service on a private IP, or a loopback port. The guard's
job is to ensure an outbound request only ever reaches a **public unicast**
address, and that the address it validated is the address it connects to.

## Bypasses defended

| Class | Technique | Defence |
|-------|-----------|---------|
| **DNS rebinding (TOCTOU)** | DNS returns a public IP at check, an internal IP at connect | Resolve once, pin via `CURLOPT_RESOLVE`, verify the connected IP (`on_stats`) |
| **Redirect hop** | `30x` `Location:` to an internal host | Redirects disabled on guarded requests |
| **IP encodings** | `2130706433`, `0x7f000001` | Normalized before validation (redirect mode) |
| **IPv6 transition** | `::ffff:127.0.0.1`, `2002:7f00:1::` (6to4), `64:ff9b::` (NAT64), Teredo | Prefixes blocked wholesale **and** embedded IPv4 extracted + re-checked ([CVE-2026-48736](https://symfony.com/blog/cve-2026-48736-iputils-private-subnets-omits-ipv6-transition-forms-ssrf-bypass-in-noprivatenetworkhttpclient) class) |
| **Cloud metadata** | `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`, `metadata.google.internal` | Explicit IP + name block, plus link-local range |
| **Reserved ranges** | RFC 1918, loopback, link-local, ULA, CGNAT, TEST-NET, multicast | CIDR block-list, IPv4 + IPv6 |
| **URL tricks** | `user:pass@host`, `.internal`/`.local` suffixes, `file://` | Credential + suffix + scheme checks; validation targets the *resolved IP* |

## Honest scope

This is **defense in depth, not a complete fix.** Three limits you must design
around:

1. **Network egress control is the real answer.** A firewall / security-group /
   egress proxy that can only reach approved destinations closes SSRF completely —
   it doesn't depend on parsing the URL the way the HTTP client does. Run this guard
   *and* restrict egress; block `169.254.169.254` at the network and require IMDSv2
   (hop-limit 1, token-required).
2. **A proxy in the path defeats pinning.** When `HTTP_PROXY` is set, the proxy
   resolves DNS, not this library, so connection pinning and rebinding protection no
   longer apply. Rely on the proxy's own egress policy there.
3. **Response content is out of scope.** The guard controls *where* a request goes,
   not *what comes back* — SSRF-via-response, stored XSS, and unsafe deserialization
   of the response remain the caller's responsibility.

## Reporting

Found a bypass — a URL the guard accepts that reaches a private/reserved/metadata
address? That's the report we most want. See [SECURITY.md](../../SECURITY.md) for the
private channel and safe-harbor terms.
