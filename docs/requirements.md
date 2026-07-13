---
title: Requirements
description: Runtime and framework versions cboxdk/laravel-ssrf needs
weight: 2
---

# Requirements

Taken directly from the package's `composer.json` — the resolver enforces them,
so this page only explains them.

## Runtime

| Requirement | Version | Why |
|---|---|---|
| PHP | `^8.4` | Uses PHP 8.4 language features throughout. |

No non-default PHP extensions are required to validate URLs. DNS resolution uses
PHP's built-in resolver.

## Framework

| Requirement | Version |
|---|---|
| Laravel (`illuminate/*`) | `^12.0 \|\| ^13.0` |
| `symfony/http-foundation` | `^7.0 \|\| ^8.0` |

Registered via package auto-discovery — no manual provider wiring.

## Connection pinning (production note)

`pinnedOptions()` pins an outbound request to the exact IPs the guard validated,
via Guzzle's cURL `resolve` option. That path needs the **cURL** HTTP handler
(the default for Laravel's HTTP client). Behind a forward HTTP proxy the proxy
does its own resolution, which defeats pinning — see
[Security](security/_index.md) for the honest scope.
