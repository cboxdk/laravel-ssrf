<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Contracts;

/**
 * Resolves a hostname to the IP addresses it points at. Abstracted so the guard
 * can be tested deterministically (bind a fake) and so a deployment can supply a
 * resolver that consults a pinned/internal DNS view.
 */
interface Resolver
{
    /**
     * @return list<string> every A/AAAA address for $host (empty if it does not resolve)
     */
    public function resolve(string $host): array;
}
