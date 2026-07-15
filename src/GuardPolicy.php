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
        public bool $allowCredentials = false,
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
            allowCredentials: ($config['allow_credentials'] ?? false) !== false,
            blockedHosts: self::lowerList($config['blocked_hosts'] ?? []),
            blockedHostSuffixes: self::lowerList($config['blocked_host_suffixes'] ?? []),
            blockedIps: self::lowerList($config['blocked_ips'] ?? []),
            blockedCidrs: self::stringList($config['blocked_cidrs'] ?? []),
        );
    }

    /**
     * A per-call variant of this policy: override only the scheme allow-list
     * and/or the credential allowance, inheriting every other setting (enforce,
     * pinning, and the blocked host/IP/CIDR lists). A `null` argument leaves that
     * dimension unchanged. Lets one guard serve several outbound sinks with
     * different scheme/credential rules from a single shared block-list policy.
     *
     * @param  list<string>|null  $allowedSchemes
     */
    public function with(?array $allowedSchemes = null, ?bool $allowCredentials = null): self
    {
        return new self(
            allowedSchemes: $allowedSchemes !== null ? self::lowerList($allowedSchemes) : $this->allowedSchemes,
            enforce: $this->enforce,
            pinDns: $this->pinDns,
            allowCredentials: $allowCredentials ?? $this->allowCredentials,
            blockedHosts: $this->blockedHosts,
            blockedHostSuffixes: $this->blockedHostSuffixes,
            blockedIps: $this->blockedIps,
            blockedCidrs: $this->blockedCidrs,
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
