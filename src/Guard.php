<?php

declare(strict_types=1);

namespace Cbox\Ssrf;

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use GuzzleHttp\TransferStats;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * The SSRF guard. A URL is safe only when its scheme is allowed, it carries no
 * embedded credentials, its host is not on a block-list, and EVERY address the
 * host resolves to is public unicast (not private, loopback, link-local,
 * cloud-metadata, or reserved) — for both IPv4 and IPv6.
 */
final class Guard implements UrlGuard
{
    public function __construct(
        private readonly GuardPolicy $policy,
        private readonly Resolver $resolver,
    ) {}

    public function assertSafe(string $url): void
    {
        $this->inspect($url, resolveDns: true);
    }

    public function isSafe(string $url): bool
    {
        try {
            $this->assertSafe($url);

            return true;
        } catch (BlockedUrl) {
            return false;
        }
    }

    public function assertSafeRedirect(string $url): void
    {
        // Browser-redirect mode: don't resolve DNS (the browser does that at
        // click time), but still block IP literals in private/reserved ranges
        // and blocked hosts.
        $this->inspect($url, resolveDns: false);
    }

    public function pinnedOptions(string $url): array
    {
        $inspection = $this->inspect($url, resolveDns: true);
        $ips = $inspection['ips'];

        if ($ips === [] || ! $this->policy->pinDns) {
            // No redirects regardless — a 30x to a fresh host is another SSRF path.
            return ['allow_redirects' => false];
        }

        $host = $inspection['host'];

        $options = [
            'allow_redirects' => false,
            // Post-connection consistency check: if the handler reports the IP it
            // actually connected to, reject anything not in the validated set.
            'on_stats' => static function (TransferStats $stats) use ($host, $ips): void {
                $connected = $stats->getHandlerStats()['primary_ip'] ?? null;

                if (is_string($connected) && $connected !== '' && ! in_array($connected, $ips, true)) {
                    throw BlockedUrl::make("connected IP [{$connected}] for host [{$host}] is not in the validated set");
                }
            },
        ];

        if (defined('CURLOPT_RESOLVE')) {
            $options['curl'] = [
                CURLOPT_RESOLVE => array_map(
                    static fn (string $ip): string => $host.':'.$inspection['port'].':'.(str_contains($ip, ':') ? '['.$ip.']' : $ip),
                    $ips,
                ),
            ];
        }

        return $options;
    }

    /**
     * @return array{host: string, port: int, ips: list<string>}
     */
    private function inspect(string $url, bool $resolveDns): array
    {
        $url = trim($url);

        if ($url === '') {
            throw BlockedUrl::make('URL is empty');
        }

        $parts = parse_url($url);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw BlockedUrl::make('URL must have a scheme and host');
        }

        $scheme = strtolower((string) $parts['scheme']);

        if (! in_array($scheme, $this->policy->allowedSchemes, true)) {
            throw BlockedUrl::make("scheme [{$scheme}] is not allowed");
        }

        // Embedded credentials (user:pass@host) are a classic SSRF/obfuscation trick.
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw BlockedUrl::make('credentials in the URL are not allowed');
        }

        $host = $this->normalizeHost((string) $parts['host']);

        if ($host === '') {
            throw BlockedUrl::make('URL host is empty');
        }

        if ($this->isBlockedHost($host)) {
            throw BlockedUrl::make("host [{$host}] is blocked");
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        // Enforcement can be disabled for on-prem installs that must reach
        // internal hosts; scheme/credential/host-block checks above still run.
        if (! $this->policy->enforce) {
            return ['host' => $host, 'port' => $port, 'ips' => []];
        }

        $ips = $resolveDns ? $this->resolveHost($host) : $this->ipLiteral($host);

        foreach ($ips as $ip) {
            $this->assertPublicIp($ip, $host);
        }

        return ['host' => $host, 'port' => $port, 'ips' => $ips];
    }

    /**
     * @return list<string>
     */
    private function resolveHost(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        $ips = $this->resolver->resolve($host);

        if ($ips === []) {
            throw BlockedUrl::make("host [{$host}] does not resolve");
        }

        return $ips;
    }

    /**
     * IP-literal-only resolution for browser-redirect mode. Also normalizes the
     * integer- and hex-encoded IPv4 forms browsers accept (e.g. 2130706433 or
     * 0x7f000001 → 127.0.0.1) so they can't slip a loopback past the checks.
     *
     * @return list<string>
     */
    private function ipLiteral(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }

        if (ctype_digit($host) && (float) $host <= 4294967295.0) {
            return [long2ip((int) $host)];
        }

        if (str_starts_with($host, '0x')) {
            $hex = substr($host, 2);

            if ($hex !== '' && ctype_xdigit($hex) && strlen($hex) <= 8) {
                return [long2ip((int) hexdec($hex))];
            }
        }

        return [];
    }

    private function assertPublicIp(string $ip, string $host): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw BlockedUrl::make("host [{$host}] resolved to an invalid IP [{$ip}]");
        }

        if (in_array(strtolower($ip), $this->policy->blockedIps, true)) {
            throw BlockedUrl::make("host [{$host}] resolves to a blocked address [{$ip}]");
        }

        if ($this->policy->blockedCidrs !== [] && IpUtils::checkIp($ip, $this->policy->blockedCidrs)) {
            throw BlockedUrl::make("host [{$host}] resolves to a non-public address [{$ip}]");
        }

        // An IPv6 transition form can embed a private IPv4 (6to4, NAT64, IPv4-
        // mapped/compatible). Extract and re-check the embedded v4 so a poisoned
        // custom CIDR list can't leave the door open (CVE-2026-48736 class).
        $embedded = $this->embeddedIpv4($ip);

        if ($embedded !== null && $embedded !== $ip) {
            $this->assertPublicIp($embedded, $host);
        }
    }

    /**
     * The IPv4 address embedded in an IPv6 transition form, or null if none.
     */
    private function embeddedIpv4(string $ip): ?string
    {
        $packed = @inet_pton($ip);

        // Only 16-byte (IPv6) addresses can embed an IPv4.
        if ($packed === false || strlen($packed) !== 16) {
            return null;
        }

        $unpacked = unpack('C*', $packed);

        if ($unpacked === false) {
            return null;
        }

        // Cast each unpacked byte to int so the arithmetic/concatenation below is
        // well-typed.
        $bytes = array_map(static fn (mixed $b): int => is_int($b) ? $b : 0, array_values($unpacked));

        if (count($bytes) !== 16) {
            return null;
        }

        $tail = static fn (): string => $bytes[12].'.'.$bytes[13].'.'.$bytes[14].'.'.$bytes[15];

        // 6to4: 2002:AABB:CCDD::/16 → A.B.C.D lives in bytes 2..5.
        if ($bytes[0] === 0x20 && $bytes[1] === 0x02) {
            return $bytes[2].'.'.$bytes[3].'.'.$bytes[4].'.'.$bytes[5];
        }

        // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible/NAT64 (embedded in the
        // low 32 bits): the embedded v4 is the last four bytes.
        $high96Zero = array_sum(array_slice($bytes, 0, 10)) === 0;
        $isMapped = $high96Zero && $bytes[10] === 0xFF && $bytes[11] === 0xFF;
        $isCompatible = array_sum(array_slice($bytes, 0, 12)) === 0;
        $isNat64 = $bytes[0] === 0x00 && $bytes[1] === 0x64 && $bytes[2] === 0xFF && $bytes[3] === 0x9B;

        return ($isMapped || $isCompatible || $isNat64) ? $tail() : null;
    }

    private function normalizeHost(string $host): string
    {
        return strtolower(rtrim(trim($host, '[]'), '.'));
    }

    private function isBlockedHost(string $host): bool
    {
        if (in_array($host, $this->policy->blockedHosts, true)) {
            return true;
        }

        foreach ($this->policy->blockedHostSuffixes as $suffix) {
            if (str_ends_with($host, $suffix)) {
                return true;
            }
        }

        return false;
    }
}
