---
title: Quickstart
description: Guard an outbound request in one line
weight: 2
---

# Quickstart

## Guard an outbound HTTP request

The `Http::ssrf()` macro validates the URL, pins the connection, and disables
redirects — then it's the normal Laravel HTTP client:

```php
use Illuminate\Support\Facades\Http;

$response = Http::ssrf($endpoint)
    ->withHeaders(['X-Signature' => $signature])
    ->post($endpoint, $payload);
```

If `$endpoint` is unsafe, the macro throws `Cbox\Ssrf\Exceptions\BlockedUrl`
*before* any request is made. Catch it to turn it into a domain error:

```php
use Cbox\Ssrf\Exceptions\BlockedUrl;

try {
    Http::ssrf($endpoint)->post($endpoint, $payload);
} catch (BlockedUrl $e) {
    // Log it; do not echo $e->getMessage() to an untrusted caller — it confirms
    // internal reachability.
    report($e);
}
```

## Validate a user-supplied URL

Reject an unsafe URL at the edge, before you ever store it:

```php
use Cbox\Ssrf\Rules\PublicUrl;

$data = $request->validate([
    'webhook_url' => ['required', 'url', new PublicUrl],
]);
```

## That's it

Everything else — custom clients, browser-redirect validation, tuning the policy —
builds on `app(Cbox\Ssrf\Contracts\UrlGuard::class)`. See the
[Cookbook](../cookbook.md).
