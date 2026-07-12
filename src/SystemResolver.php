<?php

declare(strict_types=1);

namespace Cbox\Ssrf;

use Cbox\Ssrf\Contracts\Resolver;

/**
 * The production resolver: consults the system DNS for both A and AAAA records.
 * IP literals are returned as-is.
 */
final class SystemResolver implements Resolver
{
    public function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = [];

        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;

            if (is_string($ip) && $ip !== '') {
                $ips[] = $ip;
            }
        }

        // Fallback for environments where dns_get_record is restricted.
        foreach (@gethostbynamel($host) ?: [] as $ip) {
            if ($ip !== '') {
                $ips[] = $ip;
            }
        }

        return array_values(array_unique($ips));
    }
}
