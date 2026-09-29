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
class Guard implements UrlGuard
{
    public function __construct(
        private readonly GuardPolicy $policy,
        private readonly Resolver $resolver,
    ) {}

    public function assertSafe(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): void
    {
        $this->inspect($url, $this->policyFor($allowedSchemes, $allowCredentials), resolveDns: true);
    }

    public function isSafe(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): bool
    {
        try {
            $this->assertSafe($url, $allowedSchemes, $allowCredentials);

            return true;
        } catch (BlockedUrl) {
            return false;
        }
    }

    public function assertSafeRedirect(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): void
    {
        // Browser-redirect mode: don't resolve DNS (the browser does that at
        // click time), but still block IP literals in private/reserved ranges
        // and blocked hosts.
        $this->inspect($url, $this->policyFor($allowedSchemes, $allowCredentials), resolveDns: false);
    }

    public function pinnedOptions(string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): array
    {
        $policy = $this->policyFor($allowedSchemes, $allowCredentials);
        $inspection = $this->inspect($url, $policy, resolveDns: true);
        $ips = $inspection['ips'];

        if ($ips === [] || ! $policy->pinDns) {
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
            // ONE entry for the host:port, listing every validated address — not one
            // entry per address.
            //
            // curl treats a second entry for the same `host:port` as a REPLACEMENT, not
            // an addition, so a list of two produced a pin to whichever address happened
            // to sort last and silently discarded the rest. For a dual-stack host whose
            // AAAA sorts last (accounts.google.com does) that meant every request was
            // pinned to IPv6 alone — and on any machine without IPv6 connectivity every
            // guarded call failed to connect, with no fallback to the IPv4 address that
            // had been validated a moment earlier.
            //
            // The failure is invisible from the code: DNS resolved, the addresses were
            // checked, the pin looked complete, and the request died at connect time
            // with a transport error naming neither the pin nor the protocol. It also
            // flips with the environment, so it presents as "works on my machine".
            //
            // curl's documented format is `host:port:addr[,addr]...`, and with the whole
            // list in one entry it does Happy Eyeballs across the family as usual.
            $addresses = implode(',', array_map(
                // Bracketed, because a bare IPv6 address is ambiguous against the
                // colon separators the format itself uses.
                static fn (string $ip): string => str_contains($ip, ':') ? '['.$ip.']' : $ip,
                $ips,
            ));

            // The pin must name the host exactly as curl will look it up — and curl
            // looks it up as WRITTEN in the URL. The guard validates the normalized
            // form (`example.com.` → `example.com`), but curl matches a resolve entry
            // against the name in the URL, trailing dot included, so a pin for
            // `example.com` does nothing for `https://example.com./`. curl then falls
            // back to its own DNS lookup — the rebinding window the pin exists to
            // close — and `on_stats` only fires after the request has already gone out.
            //
            // So pin every name curl might look up — see lookupNames(). Different
            // names are different entries, so this does not trip the replacement rule
            // above. Case needs no such treatment — curl lowercases both sides of the
            // match.
            $options['curl'] = [
                CURLOPT_RESOLVE => array_map(
                    static fn (string $name): string => $name.':'.$inspection['port'].':'.$addresses,
                    $inspection['lookupNames'],
                ),
            ];
        }

        return $options;
    }

    /**
     * The effective policy for a call: the configured policy, or a per-call
     * variant when a scheme override or credential allowance is supplied.
     *
     * @param  list<string>|null  $allowedSchemes
     */
    private function policyFor(?array $allowedSchemes, bool $allowCredentials): GuardPolicy
    {
        if ($allowedSchemes === null && ! $allowCredentials) {
            return $this->policy;
        }

        // A `false` $allowCredentials inherits the configured policy (null),
        // rather than force-denying — so the global default still applies.
        return $this->policy->with(
            allowedSchemes: $allowedSchemes,
            allowCredentials: $allowCredentials ? true : null,
        );
    }

    /**
     * `host` is the normalized ASCII form every check runs against; `lookupNames` are
     * the names the HTTP client may actually look up, which the pin has to cover.
     *
     * @return array{host: string, lookupNames: list<string>, port: int, ips: list<string>}
     */
    private function inspect(string $url, GuardPolicy $policy, bool $resolveDns): array
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

        if (! in_array($scheme, $policy->allowedSchemes, true)) {
            throw BlockedUrl::make("scheme [{$scheme}] is not allowed");
        }

        // Embedded credentials (user:pass@host) are a classic SSRF/obfuscation
        // trick; permitted only when the caller opts in (e.g. a git deploy token).
        if (! $policy->allowCredentials && (isset($parts['user']) || isset($parts['pass']))) {
            throw BlockedUrl::make('credentials in the URL are not allowed');
        }

        $written = strtolower(trim((string) $parts['host'], '[]'));

        // curl, like a browser, percent-decodes the host before looking it up, so
        // `%6cocalhost` reaches `localhost` while matching no block-list entry here,
        // and `%61.evil.test` validates a DNS name curl never resolves. No legitimate
        // URL percent-encodes its host, so refuse rather than re-implement the decoding.
        if (str_contains($written, '%')) {
            throw BlockedUrl::make('a percent-encoded host is not allowed');
        }

        $ascii = $this->asciiHost($written);
        $host = $this->normalizeHost($ascii);

        if ($host === '') {
            throw BlockedUrl::make('URL host is empty');
        }

        if ($this->isBlockedHost($host, $policy)) {
            throw BlockedUrl::make("host [{$host}] is blocked");
        }

        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        // Enforcement can be disabled for on-prem installs that must reach
        // internal hosts; scheme/credential/host-block checks above still run.
        if (! $policy->enforce) {
            return ['host' => $host, 'lookupNames' => $this->lookupNames($host, $ascii, $written), 'port' => $port, 'ips' => []];
        }

        $ips = $resolveDns ? $this->resolveHost($host) : $this->ipLiteral($host);

        foreach ($ips as $ip) {
            $this->assertPublicIp($ip, $host, $policy);
        }

        return ['host' => $host, 'lookupNames' => $this->lookupNames($host, $ascii, $written), 'port' => $port, 'ips' => $ips];
    }

    /**
     * The ASCII (punycode) form of a host, mapped the way curl maps it.
     *
     * An internationalized host is not looked up as written. An IDN-capable curl —
     * which is most builds — converts it with UTS #46 non-transitional processing
     * first (`bücher.test` → `xn--bcher-kva.test`, `faß.test` → `xn--fa-hia.test`),
     * and browsers do the same. Every check therefore has to run against that ASCII
     * name, or the guard validates one DNS name while the client connects to another.
     *
     * The mapping does more than punycode: it folds compatibility forms, so
     * `ｌｏｃａｌｈｏｓｔ` (fullwidth) becomes `localhost`, `metadata.google。internal`
     * (ideographic full stop) becomes `metadata.google.internal`, and `１２７.０.０.１`
     * becomes `127.0.0.1`. Compared as written, all three slipped past the host
     * block-list and the IP-literal check — in redirect mode and with enforcement off,
     * where no DNS lookup was there to fail closed.
     *
     * A host that does not map cleanly is refused rather than passed through, and so
     * is any non-ASCII host when ext-intl is missing: without the mapping there is no
     * way to know which name the client will resolve.
     */
    private function asciiHost(string $host): string
    {
        // Pure ASCII is left alone, exactly as curl leaves it alone.
        if (! preg_match('/[^\x00-\x7F]/', $host)) {
            return $host;
        }

        if (! function_exists('idn_to_ascii')) {
            throw BlockedUrl::make('a non-ASCII host requires ext-intl to validate safely');
        }

        $ascii = idn_to_ascii(
            $host,
            IDNA_NONTRANSITIONAL_TO_ASCII | IDNA_CHECK_BIDI | IDNA_CHECK_CONTEXTJ,
            INTL_IDNA_VARIANT_UTS46,
            $info,
        );

        if (! is_string($ascii) || $ascii === '' || (is_array($info) && ($info['errors'] ?? 0) !== 0)) {
            throw BlockedUrl::make('host is not a valid internationalized domain name');
        }

        return strtolower($ascii);
    }

    /**
     * Every name the HTTP client may look up for this host, for the resolve pin.
     *
     * curl matches a `CURLOPT_RESOLVE` entry against the name it is about to resolve,
     * so a pin on any other spelling is silently ignored and curl goes to DNS — the
     * rebinding window the pin exists to close, with `on_stats` firing only after the
     * request has already gone out. That name is the host as written in the URL,
     * trailing dot included (`example.test.` does not match a pin for `example.test`),
     * converted to punycode when it is internationalized. Pinned, in order:
     *
     * - the normalized ASCII host, for a client that normalizes before looking up;
     * - the ASCII host as written, which is what IDN-capable curl looks up;
     * - the host as written in UTF-8, which is what a curl built WITHOUT IDN support
     *   hands to the system resolver.
     *
     * Each entry carries the addresses validated for the normalized host, so whichever
     * one curl matches, it connects only to validated addresses.
     *
     * @return list<string>
     */
    private function lookupNames(string $host, string $ascii, string $written): array
    {
        return array_values(array_unique([$host, $ascii, $written]));
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

    private function assertPublicIp(string $ip, string $host, GuardPolicy $policy): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw BlockedUrl::make("host [{$host}] resolved to an invalid IP [{$ip}]");
        }

        if (in_array(strtolower($ip), $policy->blockedIps, true)) {
            throw BlockedUrl::make("host [{$host}] resolves to a blocked address [{$ip}]");
        }

        if ($policy->blockedCidrs !== [] && IpUtils::checkIp($ip, $policy->blockedCidrs)) {
            throw BlockedUrl::make("host [{$host}] resolves to a non-public address [{$ip}]");
        }

        // An IPv6 transition form can embed a private IPv4 (6to4, NAT64, IPv4-
        // mapped/compatible). Extract and re-check the embedded v4 so a poisoned
        // custom CIDR list can't leave the door open (CVE-2026-48736 class).
        $embedded = $this->embeddedIpv4($ip);

        if ($embedded !== null && $embedded !== $ip) {
            $this->assertPublicIp($embedded, $host, $policy);
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

    private function isBlockedHost(string $host, GuardPolicy $policy): bool
    {
        if (in_array($host, $policy->blockedHosts, true)) {
            return true;
        }

        foreach ($policy->blockedHostSuffixes as $suffix) {
            if (str_ends_with($host, $suffix)) {
                return true;
            }
        }

        return false;
    }
}
