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
     * @throws BlockedUrl
     */
    public function assertSafe(string $url): void;

    /**
     * The non-throwing form of {@see assertSafe()}.
     */
    public function isSafe(string $url): bool;

    /**
     * Assert a URL is safe to hand to the user's browser as a redirect target
     * (e.g. an OAuth `authorize_url`) rather than fetch server-side. Blocks IP
     * literals in private/reserved ranges and blocked hosts, but does not resolve
     * DNS — the browser resolves at click time.
     *
     * @throws BlockedUrl
     */
    public function assertSafeRedirect(string $url): void;

    /**
     * Guzzle request options that pin the connection to the validated addresses
     * and disable redirect-following, for a request that has already passed
     * {@see assertSafe()}. Spread these into the HTTP client's options.
     *
     * @return array<string, mixed>
     */
    public function pinnedOptions(string $url): array;
}
