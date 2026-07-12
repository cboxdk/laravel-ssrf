---
title: Testing
description: Deterministic SSRF tests with the FakeResolver
weight: 7
---

# Testing

Real DNS is non-deterministic and slow, and you want to prove the guard blocks
addresses you can't actually route to in CI. Bind the shipped `FakeResolver` to
make resolution a fixture.

```php
use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Testing\FakeResolver;

beforeEach(function () {
    $this->app->instance(Resolver::class, new FakeResolver([
        'good.test' => ['93.184.216.34'],
        'evil.test' => ['169.254.169.254'],
    ]));
});

it('blocks a webhook that resolves to cloud metadata', function () {
    expect(fn () => app(UrlGuard::class)->assertSafe('https://evil.test'))
        ->toThrow(Cbox\Ssrf\Exceptions\BlockedUrl::class);
});
```

## Testing your webhook delivery without real hosts

Combine `FakeResolver` with Laravel's `Http::fake()`:

```php
Http::fake(['good.test/*' => Http::response(['ok' => true])]);

$response = Http::ssrf('https://good.test/hook')->post('https://good.test/hook');
expect($response->json('ok'))->toBeTrue();
```

## What the package's own suite covers

The package is proven against real SSRF vectors, not mocks that return success:
private/loopback/link-local/CGNAT addresses, cloud-metadata IPs, IPv6 transition
forms (6to4, NAT64, IPv4-mapped), integer/hex IP literals, embedded credentials,
disallowed schemes, and blocked host suffixes. See `tests/Feature/`.
