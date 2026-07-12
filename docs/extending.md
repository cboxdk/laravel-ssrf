---
title: Extending
description: Custom resolvers, policy, and clients
weight: 6
---

# Extending

Everything is a contract bound in the container, so you override by rebinding.

## A custom resolver

Supply your own DNS view — an internal resolver, a cache, a pinned map — by binding
the `Resolver` contract:

```php
use Cbox\Ssrf\Contracts\Resolver;

$this->app->singleton(Resolver::class, function () {
    return new class implements Resolver {
        public function resolve(string $host): array
        {
            // consult your resolver; return a list of IP strings
        }
    };
});
```

The guard calls this once per validation and pins the connection to what it
returns, so a resolver that already enforces an internal policy composes cleanly.

## Tuning the policy

The policy is built from `config/ssrf.php`. Publish it and edit the lists; the
`GuardPolicy` singleton reads them at boot. For a fully programmatic policy, bind
`GuardPolicy` yourself:

```php
use Cbox\Ssrf\GuardPolicy;

$this->app->singleton(GuardPolicy::class, fn () => new GuardPolicy(
    allowedSchemes: ['https'],           // https only
    blockedHostSuffixes: ['.internal'],
    // …
));
```

## Wrapping a different HTTP client

The guard is client-agnostic. `pinnedOptions()` returns Guzzle-style options
(`allow_redirects`, `on_stats`, `curl`), which Laravel's HTTP client accepts
directly. For a bespoke Guzzle client, spread them into your request options after
calling `assertSafe()`:

```php
$guard->assertSafe($url);
$client->request('GET', $url, $guard->pinnedOptions($url));
```

## Swapping the whole guard

Bind your own `UrlGuard` implementation to replace the behaviour entirely — the
`Http::ssrf()` macro, the `PublicUrl` rule, and every caller resolve the contract,
so they all pick up your implementation.
