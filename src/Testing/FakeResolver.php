<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Testing;

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\SystemResolver;

/**
 * A deterministic resolver for tests: maps hostnames to fixed IP lists so the
 * SSRF guard can be exercised without touching real DNS. Bind it in place of the
 * {@see SystemResolver}:
 *
 *   $this->app->instance(Resolver::class, new FakeResolver(['evil.test' => ['169.254.169.254']]));
 */
final class FakeResolver implements Resolver
{
    /**
     * @param  array<string, list<string>>  $map  hostname (lowercase) => IPs
     */
    public function __construct(private array $map = []) {}

    /**
     * @param  list<string>  $ips
     */
    public function set(string $host, array $ips): self
    {
        $this->map[strtolower($host)] = $ips;

        return $this;
    }

    public function resolve(string $host): array
    {
        return $this->map[strtolower($host)] ?? [];
    }
}
