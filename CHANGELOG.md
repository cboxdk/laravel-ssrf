# Changelog

All notable changes to `cboxdk/laravel-ssrf` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0]

### Added

- **`Cbox\Ssrf\Testing\InteractsWithSsrf`** — the test-side wiring the package was
  missing. Compose it into your base `TestCase` for `fakeSsrfDns()`,
  `withSsrfConfig()`, `ssrfGuard()` and `refreshSsrfGuard()`.

  It exists because the guard and its policy are container **singletons** built from
  config. If anything has already resolved the guard, a later
  `config(['ssrf.enforce' => false])` silently changes nothing and the test asserts
  against the old policy — a green test proving the wrong thing. Every helper drops
  both singletons first. The package's own suite now goes through the trait rather
  than hand-rolling `$this->app->instance(Resolver::class, ...)`, so the trait is
  exercised by every test rather than merely shipped.

### Fixed

- **`SECURITY.md` described the package as pre-1.0.** It told researchers this was a
  "pre-1.0, best-effort" project and that only the latest `0.x` tag received security
  fixes, while the package was at 1.2.0 — a supported-versions statement naming a
  version scheme the package had already left. It now states the real policy: latest
  `1.x` only, no LTS branch, no backports, and explicitly no response-time guarantee.

- `branch-alias` still declared `dev-main` as `1.0.x-dev` on a 1.2 package; it now
  tracks `1.3.x-dev`.

### Changed

- `pestphp/pest` widened to `^4.0 || ^5.0` (was `^3.5 || ^4.0`), so the dev toolchain
  covers the current major and the previous one. Pest 5 tracks PHPUnit 13, not Laravel;
  verified on both CI cells — testbench `^11` resolves Pest 5.0.3 / PHPUnit 13.2.6, and
  testbench `^10` resolves Pest 4.7.7 / PHPUnit 12.5.33, with the full suite green on
  each.

## [1.2.0]

### Added

- **`Http::ssrf()->get($url)` — the URL is now guarded at send time.** The macro's
  `$url` argument is optional, and the client validates and pins whatever URL it is
  finally given. One client can serve a loop of endpoints, each guarded and pinned on
  its own.

  This closes a hole in the old shape rather than just tidying it. `Http::ssrf($url)`
  had to be handed the URL up front because `CURLOPT_RESOLVE` and `on_stats` are Guzzle
  *options*, fixed when the request is configured rather than when it is sent — hence
  `Http::ssrf($url)->get($url)`. But the two URLs were independent, so
  `Http::ssrf($safe)->get($evil)` validated one and fetched the other. With
  `pin_dns => false` or `enforce => false`, `pinnedOptions()` returns neither `on_stats`
  nor `curl`, so **nothing at all** checked the URL actually fetched. Even with pinning
  on, `on_stats` runs *after* the transfer: the request to the attacker's host is still
  sent, so blind SSRF succeeds and only the response is withheld.

  Guarding at send time makes the validated URL and the fetched URL the same URL by
  construction. The guard runs under `Http::fake()` as well, so tests still see
  `BlockedUrl`.

- `Cbox\Ssrf\Http\GuardRequestMiddleware` and `Cbox\Ssrf\Http\GuardedHandler`, the Guzzle
  middleware behind the above. `allow_redirects` stays eager on the PendingRequest —
  Laravel pushes caller middleware *inside* Guzzle's redirect middleware, which has
  already read its options by the time the guard runs.

### Changed

- Package classes are no longer `final`, so hosts can extend or decorate what the
  package ships (`Guard`, `GuardPolicy`, `SystemResolver`, `SsrfServiceProvider`,
  `BlockedUrl`, `PublicUrl`, `FakeResolver`).

**Backwards compatible.** `Http::ssrf($url)` still works and still fails fast, before a
request object is built — and it is now *also* correct when the URL passed to `get()`
differs, because the sent URL is guarded regardless.

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

- **`sbom.json` named the wrong producer.** `bin/generate-sbom.php` was copied from
  `cboxdk/laravel-id` and still hard-coded that package's name as the SBOM's producing
  tool and as the seed for its deterministic serial number, so this package's
  supply-chain record attributed itself to another package. Both are now derived from
  `composer.json`, which also guarantees two cboxdk packages resolving the same
  dependency set get distinct serial numbers.

### Internal

- CI's SBOM freshness gate compared exact resolved versions. Because a library commits
  no `composer.lock`, CI resolves fresh and picks up any upstream patch released since
  the maintainer last ran `composer sbom`, so the gate could not be satisfied and had
  been failing on unrelated `symfony/*` patches — including on the commit carrying the
  DNS-pinning fix. It now compares the dependency *set* and runs on release tags,
  matching `cboxdk/laravel-id`; version drift on `main` is reported as a notice.

- The `on_stats` test now drives the callback with a real `TransferStats` for each
  validated address and for one outside the set, instead of only asserting the option
  exists — the previous form would have passed even with the check deleted.

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
