---
title: Installation
description: Install and configure the SSRF guard
weight: 1
---

# Installation

```bash
composer require cboxdk/laravel-ssrf
```

The `SsrfServiceProvider` is auto-discovered — no manual registration. Out of the
box it enforces a secure-by-default policy (public unicast only, http/https only,
DNS pinning on).

## Publish the config (optional)

```bash
php artisan vendor:publish --tag=ssrf-config
```

This writes `config/ssrf.php`, where you can adjust:

| Key | Purpose |
|-----|---------|
| `allowed_schemes` | URL schemes permitted (default `http`, `https`) |
| `enforce` | Master switch; `false` skips DNS/IP checks (on-prem installs) |
| `pin_dns` | Pin the connection to resolved IPs (default `true`) |
| `blocked_hosts` | Exact hostnames to refuse |
| `blocked_host_suffixes` | Host suffixes to refuse (`.internal`, `.local`, …) |
| `blocked_ips` | Individual addresses to refuse (cloud metadata) |
| `blocked_cidrs` | CIDR ranges to refuse (private/reserved/transition) |

Environment overrides: `SSRF_ENFORCE`.

## Requirements

- PHP `^8.4`
- Laravel 12 (`illuminate/*` `^12`)

`ext-curl` is recommended: DNS pinning uses `CURLOPT_RESOLVE`, so without the cURL
handler the guard still validates and disables redirects but cannot pin the socket.
