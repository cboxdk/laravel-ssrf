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

$response = Http::ssrf()
    ->withHeaders(['X-Signature' => $signature])
    ->post($endpoint, $payload);
```

The check happens at send time on the URL the client is actually given, so the URL
that is validated is by construction the URL that is fetched.

If `$endpoint` is unsafe, `Cbox\Ssrf\Exceptions\BlockedUrl` is thrown *before* the
request leaves the process. Catch it to turn it into a domain error:

```php
use Cbox\Ssrf\Exceptions\BlockedUrl;

try {
    Http::ssrf()->post($endpoint, $payload);
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
[Cookbook](cookbook/_index.md).
