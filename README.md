# Cbox SSRF

A hardened, config-driven guard against **server-side request forgery (SSRF)** for
outbound URLs in Laravel. It validates any URL your application is about to fetch —
a webhook endpoint, an avatar/import URL, an OAuth callback — and refuses anything
that points at a private, reserved, or cloud-metadata address.

```php
use Illuminate\Support\Facades\Http;

// Validates the URL, pins the connection to the resolved public IP, and
// refuses to follow redirects — then behaves like the normal HTTP client.
$response = Http::ssrf($url)->post($url, $payload);
```

## Why

An attacker who controls a URL your server fetches can reach your internal
network: `http://169.254.169.254/latest/meta-data/` (cloud credentials),
`http://127.0.0.1:6379/` (Redis), `http://10.0.0.5/admin`. A correct SSRF guard
is deceptively hard — most home-grown checks miss DNS rebinding, redirect hops, or
IPv6 transition forms. This package handles them, and is honest about the one thing
application code cannot fully solve (see [Scope](#honest-scope)).

## What it defends against

- **DNS rebinding (TOCTOU)** — resolves once and pins the connection to that exact
  IP via `CURLOPT_RESOLVE` (keeping TLS/SNI intact), with a post-connection check
  that the socket connected to a validated address.
- **Redirect-based bypass** — refuses to follow redirects on guarded requests, so a
  `30x` to an internal host can't smuggle the request onward.
- **Alternate IP encodings** — decimal (`2130706433`) and hex (`0x7f000001`) IPv4
  literals are normalized before validation (browser-redirect mode).
- **IPv6 transition forms** — IPv4-mapped (`::ffff:127.0.0.1`), IPv4-compatible,
  6to4 (`2002::/16`), NAT64 (`64:ff9b::/96`), and Teredo (`2001::/32`) are blocked
  wholesale **and** their embedded IPv4 is extracted and re-checked (the Symfony
  [CVE-2026-48736](https://symfony.com/blog/cve-2026-48736-iputils-private-subnets-omits-ipv6-transition-forms-ssrf-bypass-in-noprivatenetworkhttpclient) class).
- **Cloud metadata** — AWS/GCP/Azure `169.254.169.254`, AWS IMDSv2 IPv6
  `fd00:ec2::254`, Alibaba `100.100.100.200`, Oracle `192.0.0.192`, and the
  `metadata.google.internal` name.
- **Reserved ranges** — loopback, RFC 1918, link-local, ULA, CGNAT
  (`100.64.0.0/10`), TEST-NET, benchmarking, and multicast, for IPv4 **and** IPv6.
- **URL tricks** — embedded credentials (`user:pass@host`), blocked host suffixes
  (`.internal`, `.local`, `.localhost`, `.intra`), and non-http(s) schemes
  (`file://`, `gopher://`, `dict://`, …).

## Install

```bash
composer require cboxdk/laravel-ssrf
```

The service provider auto-registers. Publish the config to tune the policy:

```bash
php artisan vendor:publish --tag=ssrf-config
```

## Usage

### Guard an outbound request

```php
Http::ssrf($url)->get($url);          // GET, pinned + no-redirect
Http::ssrf($url)->post($url, $data);  // throws Cbox\Ssrf\Exceptions\BlockedUrl if unsafe
```

### Validate user-supplied URLs (form input)

```php
use Cbox\Ssrf\Rules\PublicUrl;

$request->validate([
    'webhook_url' => ['required', 'url', new PublicUrl],
]);
```

### Check or assert directly

```php
use Cbox\Ssrf\Contracts\UrlGuard;

$guard = app(UrlGuard::class);

$guard->assertSafe($url);        // throws BlockedUrl on failure
$guard->isSafe($url);            // bool
$guard->pinnedOptions($url);     // Guzzle options for your own client call
```

### Per-sink scheme & credential rules

One guard (with one shared block-list policy) can serve several outbound sinks
with different rules. Pass a scheme allow-list and/or permit embedded credentials
for that call only — the IP/host enforcement is never relaxed:

```php
// Webhook sink: HTTPS only, no credentials (the default).
$guard->assertSafe($webhookUrl, ['https']);

// Git sink: HTTPS or SSH, and a deploy token in the URL is allowed.
$guard->assertSafe($repoUrl, ['https', 'ssh'], allowCredentials: true);
Http::ssrf($repoUrl, ['https', 'ssh'], allowCredentials: true)->get($repoUrl);

// Same overrides on the validation rule, per field:
$request->validate([
    'repo_url' => ['required', new PublicUrl(allowedSchemes: ['https', 'ssh'], allowCredentials: true)],
]);
```

`allowed_schemes` and `allow_credentials` in `config/ssrf.php` set the defaults; a
per-call override wins for that call and inherits every other setting.

### Browser-redirect targets (OAuth authorize URLs)

A URL you hand to the user's browser as a redirect — rather than fetch yourself —
is validated without a DNS lookup (the browser resolves it), while still blocking
IP-literal and blocked-host targets:

```php
$guard->assertSafeRedirect($authorizeUrl);
```

## Configuration

`config/ssrf.php` exposes the full policy: `allowed_schemes`, `allow_credentials`,
`blocked_hosts`, `blocked_host_suffixes`, `blocked_ips`, `blocked_cidrs`, `pin_dns`,
and a master `enforce` switch. A single-tenant/on-prem install that must reach internal hosts can
set `SSRF_ENFORCE=false` (scheme, credential, and blocked-host checks still run).

## Honest scope

An application-layer guard is **defense in depth, not a complete fix**:

- **A network egress allow-list is the real answer.** A firewall / security-group /
  egress proxy that can only reach approved destinations closes SSRF completely,
  because it doesn't depend on parsing the URL the same way the HTTP client does.
  Use this guard *and* restrict egress. Block `169.254.169.254` at the network and
  require IMDSv2 (hop-limit 1, token-required).
- **An HTTP proxy defeats connection pinning** — when `HTTP_PROXY` is set, the proxy
  resolves DNS, not this library, so rebinding protection no longer applies.
- **Response content is out of scope.** The guard controls *where* a request goes,
  not what comes back; SSRF-via-response, stored XSS, and deserialization remain the
  caller's responsibility.

## Testing

Bind the `FakeResolver` to make DNS deterministic in your own tests:

```php
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Testing\FakeResolver;

$this->app->instance(Resolver::class, new FakeResolver([
    'evil.test' => ['169.254.169.254'],
]));
```

## Documentation

Full docs in [`docs/`](docs/index.md) — [requirements](docs/requirements.md), [installation](docs/getting-started/installation.md),
[quickstart](docs/quickstart.md), [architecture](docs/core-concepts/architecture.md),
[security](docs/security/_index.md), [extending](docs/extension-points/_index.md) and [testing](docs/getting-started/testing.md).

## License

MIT © Cbox. See [LICENSE](LICENSE).
Security policy: [SECURITY.md](SECURITY.md).
