<?php

declare(strict_types=1);

namespace Cbox\Ssrf;

/**
 * The immutable policy the {@see Guard} enforces, built from config. Every list
 * is normalized (lowercased) so comparisons are case-insensitive.
 */
final readonly class GuardPolicy
{
    /**
     * @param  list<string>  $allowedSchemes
     * @param  list<string>  $blockedHosts
     * @param  list<string>  $blockedHostSuffixes
     * @param  list<string>  $blockedIps
     * @param  list<string>  $blockedCidrs
     */
    public function __construct(
        public array $allowedSchemes = ['http', 'https'],
        public bool $enforce = true,
        public bool $pinDns = true,
        public array $blockedHosts = [],
        public array $blockedHostSuffixes = [],
        public array $blockedIps = [],
        public array $blockedCidrs = [],
    ) {}

    /**
     * @param  array<array-key, mixed>  $config
     */
    public static function fromConfig(array $config): self
    {
        return new self(
            allowedSchemes: self::lowerList($config['allowed_schemes'] ?? ['http', 'https']),
            enforce: ($config['enforce'] ?? true) !== false,
            pinDns: ($config['pin_dns'] ?? true) !== false,
            blockedHosts: self::lowerList($config['blocked_hosts'] ?? []),
            blockedHostSuffixes: self::lowerList($config['blocked_host_suffixes'] ?? []),
            blockedIps: self::lowerList($config['blocked_ips'] ?? []),
            blockedCidrs: self::stringList($config['blocked_cidrs'] ?? []),
        );
    }

    /**
     * @return list<string>
     */
    private static function lowerList(mixed $value): array
    {
        return array_map(strtolower(...), self::stringList($value));
    }

    /**
     * @return list<string>
     */
    private static function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, static fn (mixed $v): bool => is_string($v) && $v !== ''));
    }
}
