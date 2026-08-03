<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Http;

use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Guzzle middleware that validates and pins the URL a request is ACTUALLY being sent
 * to, at the moment it is sent.
 *
 * This is what lets `Http::ssrf()->get($url)` exist. Before it, the macro had to be
 * given the URL up front — `Http::ssrf($url)->get($url)` — because `CURLOPT_RESOLVE`
 * and `on_stats` are Guzzle options, fixed when the request is configured rather than
 * when it is sent. Naming the URL twice was not merely awkward: the two were
 * independent, so `Http::ssrf($safe)->get($evil)` validated one URL and fetched
 * another. With DNS pinning disabled, or enforcement off, `pinnedOptions()` returns no
 * `on_stats` at all and nothing whatsoever checked the URL actually fetched. Even with
 * pinning on, `on_stats` runs AFTER the transfer — the request to the attacker's host
 * is still sent, so blind SSRF succeeds and only the response is withheld.
 *
 * Guzzle hands each middleware the request options and lets it pass amended ones on, so
 * `curl`/`on_stats` can be derived from the real URI here — they are read by the
 * innermost handler, which runs after this. `allow_redirects` is NOT set here: Laravel
 * pushes caller middleware INSIDE Guzzle's redirect middleware, which has already read
 * its options by the time this runs, so the macro sets that one eagerly on the
 * PendingRequest.
 */
class GuardRequestMiddleware
{
    /**
     * @param  list<string>|null  $allowedSchemes
     */
    public function __construct(
        private readonly ?array $allowedSchemes = null,
        private readonly bool $allowCredentials = false,
    ) {}

    /**
     * @param  callable(RequestInterface, array<string, mixed>): PromiseInterface  $handler
     */
    public function __invoke(callable $handler): GuardedHandler
    {
        return new GuardedHandler($handler, $this->allowedSchemes, $this->allowCredentials);
    }
}
