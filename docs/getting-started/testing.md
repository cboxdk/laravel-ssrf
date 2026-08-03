---
title: Testing
description: Deterministic SSRF tests with InteractsWithSsrf and the FakeResolver
weight: 7
---

# Testing

Real DNS is non-deterministic and slow, and you want to prove the guard blocks
addresses you can't actually route to in CI. Compose `InteractsWithSsrf` into your
base `TestCase` and resolution becomes a fixture.

```php
use Cbox\Ssrf\Testing\InteractsWithSsrf;

abstract class TestCase extends Orchestra\Testbench\TestCase
{
    use InteractsWithSsrf;
}
```

```php
beforeEach(function () {
    $this->fakeSsrfDns([
        'good.test' => ['93.184.216.34'],
        'evil.test' => ['169.254.169.254'],
    ]);
});

it('blocks a webhook that resolves to cloud metadata', function () {
    expect(fn () => $this->ssrfGuard()->assertSafe('https://evil.test'))
        ->toThrow(Cbox\Ssrf\Exceptions\BlockedUrl::class);
});
```

## What the trait gives you

| Method | Does |
|---|---|
| `fakeSsrfDns(array $dns)` | Answers DNS from a fixed `host => [addresses]` table. Returns the `FakeResolver`. |
| `withSsrfConfig(array $overrides)` | Sets `config('ssrf.*')` keys (given without the prefix) and reapplies them. |
| `ssrfGuard()` | The `UrlGuard` as the application sees it, rebuilt from current config and DNS. |
| `refreshSsrfGuard()` | Drops the memoised policy and guard. The others call it for you. |

That last point is the reason to use the trait rather than binding `FakeResolver`
yourself: the guard and its policy are container **singletons** built from config, so
if anything has already resolved the guard — a `beforeEach` that makes a request, say —
a later `config(['ssrf.enforce' => false])` silently changes nothing and your test
asserts against the old policy. Every helper here drops both singletons first.

## Testing your webhook delivery without real hosts

Combine `FakeResolver` with Laravel's `Http::fake()`:

```php
Http::fake(['good.test/*' => Http::response(['ok' => true])]);

$response = Http::ssrf()->post('https://good.test/hook');
expect($response->json('ok'))->toBeTrue();
```

The guard runs under `Http::fake()` too — it sits in the handler stack ahead of the
stub — so a test that posts to a private address still gets `BlockedUrl`:

```php
Http::fake();

expect(fn () => Http::ssrf()->post('https://bad.test/hook'))->toThrow(BlockedUrl::class);
```

## What the package's own suite covers

The package is proven against real SSRF vectors, not mocks that return success:
private/loopback/link-local/CGNAT addresses, cloud-metadata IPs, IPv6 transition
forms (6to4, NAT64, IPv4-mapped), integer/hex IP literals, embedded credentials,
disallowed schemes, and blocked host suffixes. See `tests/Feature/`.
