# Changelog

All notable changes to `cboxdk/laravel-ssrf` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1]

### Fixed

- **DNS pinning dropped every address but the last, breaking dual-stack hosts.**
  `pinnedOptions()` emitted one `CURLOPT_RESOLVE` entry per validated address, but curl
  treats a second entry for the same `host:port` as a REPLACEMENT rather than an
  addition. Only whichever address sorted last survived. For a dual-stack host whose
  AAAA sorts last — `accounts.google.com` is one — every guarded request was pinned to
  IPv6 alone, and on any machine without IPv6 connectivity it failed to connect with no
  fallback to the IPv4 address that had been validated moments earlier.

  Nothing about it looked wrong from the code: DNS resolved, every address was checked,
  the pin looked complete. It died at connect time with a transport error naming neither
  the pin nor the protocol, and because it depends on the host's own IPv6 routing it
  presented as "works on my machine". Found while running a real OIDC discovery against
  Google.

  Now emitted as a single entry in curl's documented `host:port:addr[,addr]...` form, so
  the whole validated set is offered and Happy Eyeballs picks a reachable one. The
  `on_stats` consistency check is unchanged and still rejects any connection to an
  address outside the validated set.

## [1.1.0]

### Added

- **Per-call scheme and credential overrides.** `UrlGuard::assertSafe()`,
  `isSafe()`, `assertSafeRedirect()`, and `pinnedOptions()` now take optional
  `?array $allowedSchemes` and `bool $allowCredentials` arguments, so one guard
  (with one shared block-list policy) can serve several outbound sinks with
  different rules — e.g. `https`-only webhooks that reject credentials, and
  `https`/`ssh` git URLs that carry a deploy token. `Http::ssrf()` and the
  `PublicUrl` validation rule accept the same overrides.
- `GuardPolicy::with(?array $allowedSchemes, ?bool $allowCredentials)` — a
  per-call variant that overrides only those two dimensions and inherits the
  configured `enforce`, `pin_dns`, and blocked host/IP/CIDR lists.
- `allow_credentials` config key (default `false`) for the global default.

Overrides never relax IP/host enforcement: a credentialed `ssh` URL to a private
address is still refused. The additions are backward compatible — existing calls
behave exactly as before.

## [1.0.0]

Initial release.

### Added

- `UrlGuard` contract and `Guard` implementation: scheme and credential checks,
  host normalization, blocked hosts/suffixes, and validation that every resolved
  address (IPv4 **and** IPv6) is public unicast.
- DNS-rebinding (TOCTOU) defence: resolve once and pin the connection to the
  validated IPs via `CURLOPT_RESOLVE` (preserving TLS/SNI), with a post-connection
  check of the IP the socket actually reached.
- Redirects disabled on guarded requests, closing the redirect-hop bypass.
- IPv6 transition-form defence — IPv4-mapped, IPv4-compatible, 6to4, NAT64, and
  Teredo prefixes blocked wholesale, and the embedded IPv4 extracted and re-checked
  (the Symfony CVE-2026-48736 class).
- Cloud-metadata blocks: AWS/GCP/Azure `169.254.169.254`, AWS IMDSv2 IPv6
  `fd00:ec2::254`, Alibaba `100.100.100.200`, Oracle `192.0.0.192`, and the
  `metadata.google.internal` name.
- Reserved-range blocks incl. CGNAT, ULA, TEST-NET, benchmarking, and multicast.
- Integer/hex IPv4 literal normalization in browser-redirect mode.
- `Http::ssrf()` client macro, `PublicUrl` validation rule, and
  `assertSafeRedirect()` for browser redirect targets.
- `Resolver` contract with a `FakeResolver` testing seam.
- Config-driven policy (`config/ssrf.php`) with an `enforce` master switch.

### Security

- Ships secure-by-default (public unicast only, http/https only, DNS pinning on).
- Documented honest scope: network egress control is the complete fix; an HTTP
  proxy in the path defeats connection pinning.

[1.0.0]: https://github.com/cboxdk/laravel-ssrf/releases/tag/v1.0.0
