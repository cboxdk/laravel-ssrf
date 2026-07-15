<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Contracts;

use Cbox\Ssrf\Exceptions\BlockedUrl;

/**
 * Guards outbound URLs against server-side request forgery.
 */
interface UrlGuard
{
    /**
     * Assert a URL is safe to fetch server-side. Validates the scheme, rejects
     * embedded credentials, resolves the host, and refuses any address that is
     * not public unicast.
     *
     * A caller may narrow (or widen) the accepted schemes and permit embedded
     * credentials for this call only — so one guard can serve several sinks with
     * different rules (e.g. `https` webhooks with no credentials, `https`/`ssh`
     * git URLs that carry a deploy token). `null` schemes inherit the configured
     * allow-list; `$allowCredentials` defaults to the configured policy.
     *
     * @param  list<string>|null  $allowedSchemes
     *
     * @throws BlockedUrl
     */
    public function assertSafe(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): void;

    /**
     * The non-throwing form of {@see assertSafe()}.
     *
     * @param  list<string>|null  $allowedSchemes
     */
    public function isSafe(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): bool;

    /**
     * Assert a URL is safe to hand to the user's browser as a redirect target
     * (e.g. an OAuth `authorize_url`) rather than fetch server-side. Blocks IP
     * literals in private/reserved ranges and blocked hosts, but does not resolve
     * DNS — the browser resolves at click time.
     *
     * @param  list<string>|null  $allowedSchemes
     *
     * @throws BlockedUrl
     */
    public function assertSafeRedirect(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): void;

    /**
     * Guzzle request options that pin the connection to the validated addresses
     * and disable redirect-following, for a request that has already passed
     * {@see assertSafe()}. Spread these into the HTTP client's options. Pass the
     * same scheme/credential overrides used for the matching {@see assertSafe()}.
     *
     * @param  list<string>|null  $allowedSchemes
     * @return array<string, mixed>
     */
    public function pinnedOptions(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): array;
}
