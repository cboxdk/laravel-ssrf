---
title: Cookbook
description: Task-oriented recipes for common SSRF-guarding needs
weight: 4
---

# Cookbook

## Deliver a webhook safely

```php
use Illuminate\Support\Facades\Http;
use Cbox\Ssrf\Exceptions\BlockedUrl;

try {
    $response = Http::ssrf($endpoint->url)
        ->timeout(10)
        ->withHeaders(['X-Signature' => $signature])
        ->post($endpoint->url, $payload);
} catch (BlockedUrl) {
    $endpoint->markUndeliverable('destination is not a public address');
    return;
}
```

The connection is pinned and redirects are disabled, so a customer can't point a
webhook at `169.254.169.254` — nor rebind DNS after registration.

## Validate at registration *and* at delivery

Validate when the URL is saved (fast feedback) **and** again immediately before each
delivery (a host's DNS can change). The macro does the delivery-time check for you;
add the rule for the save-time one:

```php
$request->validate(['url' => ['required', 'url', new PublicUrl]]);
```

## Use your own HTTP client

If you don't want the macro, pull the pinned options and merge them yourself:

```php
$guard = app(\Cbox\Ssrf\Contracts\UrlGuard::class);
$guard->assertSafe($url);

$response = Http::withOptions($guard->pinnedOptions($url))->get($url);
```

## Validate an OAuth authorize URL (handed to the browser)

A redirect target the *browser* fetches is validated without a DNS lookup, so a
legitimate corp-only IdP still saves:

```php
$guard->assertSafeRedirect($connection->authorize_url);
```

## Allow internal hosts on a single-tenant install

On-prem deployments that legitimately deliver to internal hosts can relax IP
enforcement while keeping scheme/credential/host-block checks:

```dotenv
SSRF_ENFORCE=false
```

## Add your own blocked ranges

Publish the config and extend `blocked_cidrs` / `blocked_hosts` — e.g. to block your
own management subnet:

```php
'blocked_cidrs' => [
    ...Symfony\Component\HttpFoundation\IpUtils::PRIVATE_SUBNETS,
    '203.0.113.0/24',
    '10.20.0.0/16', // internal management network
],
```
