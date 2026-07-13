---
title: Cbox SSRF
description: A hardened, config-driven SSRF guard for outbound URLs in Laravel
weight: 1
---

# Cbox SSRF

Server-side request forgery is what happens when an attacker gets your server to
make a request it shouldn't — at your cloud metadata endpoint, your Redis socket,
an internal admin panel. Any URL your application fetches on a user's behalf (a
webhook, an avatar import, an OAuth callback) is a potential SSRF vector.

`cboxdk/laravel-ssrf` is the guard you put in front of those requests. It resolves
the target, refuses anything that lands on a private/reserved/metadata address, and
pins the connection so the answer can't change between check and fetch.

## The mental model

A URL is **safe to fetch server-side** only when *all* of these hold:

1. its scheme is `http`/`https`,
2. it carries no embedded credentials,
3. its host isn't on a block-list (name or suffix), and
4. **every** address it resolves to is public unicast — for IPv4 and IPv6.

The guard then hands your HTTP client connection options that **pin** the request
to those validated addresses and **disable redirects**, closing the two bypasses
that defeat naive checks (DNS rebinding and redirect hops).

## When to use it

- Delivering **webhooks** to customer-supplied endpoints.
- **Importing** from a user-supplied URL (avatars, feeds, documents).
- Validating **OAuth/SSO callback and authorize URLs**.
- Anywhere a URL crosses the trust boundary from user input into an outbound fetch.

## Read next

- [Requirements](requirements.md) — PHP and Laravel versions
- [Installation](getting-started/installation.md)
- [Quickstart](quickstart.md) — guard a request in one line
- [Cookbook](cookbook/index.md) — webhooks, form validation, custom clients
- [Architecture](core-concepts/architecture.md) — the guard, the resolver, the policy
- [Extending](extension-points/index.md) — custom resolvers and policy
- [Testing](getting-started/testing.md) — the `FakeResolver` seam
- [Security](security/index.md) — threat model and **honest scope**
