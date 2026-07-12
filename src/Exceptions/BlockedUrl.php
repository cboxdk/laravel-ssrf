<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Exceptions;

use RuntimeException;

/**
 * Thrown when a URL is refused by the SSRF guard. The message states the reason
 * (bad scheme, embedded credentials, blocked host, non-public address); it is
 * safe to log but should not be echoed verbatim to an untrusted caller, since it
 * confirms internal-network reachability.
 */
final class BlockedUrl extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self($reason);
    }
}
