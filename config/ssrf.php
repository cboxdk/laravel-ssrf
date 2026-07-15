<?php

declare(strict_types=1);

use Symfony\Component\HttpFoundation\IpUtils;

return [

    /*
     * The URL schemes an outbound request may use. Everything else (file://,
     * gopher://, ftp://, data://, …) is refused — these are classic SSRF vectors.
     */
    'allowed_schemes' => ['http', 'https'],

    /*
     * Whether a URL may carry embedded credentials (user:pass@host) by default.
     * Kept false — credentials in a URL are a classic SSRF/obfuscation vector.
     * A specific sink that legitimately needs them (e.g. a git clone URL with a
     * deploy token) opts in per call: `assertSafe($url, allowCredentials: true)`
     * or `new PublicUrl(allowCredentials: true)`.
     */
    'allow_credentials' => false,

    /*
     * Master switch. When false, only scheme/credential checks run and DNS/IP
     * enforcement is skipped — for a single-tenant/on-prem install that must
     * legitimately reach internal hosts. Keep true in any multi-tenant deployment.
     */
    'enforce' => env('SSRF_ENFORCE', true),

    /*
     * Pin the connection to the exact IPs that were resolved and validated, and
     * fail the request if the socket connects to a different IP. This narrows the
     * DNS-rebinding (TOCTOU) window between validation and connection. A network
     * egress allow-list is the complete answer; this is defense in depth.
     */
    'pin_dns' => true,

    /*
     * Hostnames refused outright, even if DNS returns a public address for them.
     */
    'blocked_hosts' => [
        'localhost',
        'metadata.google.internal',
    ],

    /*
     * Hostname suffixes reserved for local/private resolution (RFC 6761 .localhost,
     * RFC 6762 .local mDNS) plus common intranet conventions. Blocked regardless of
     * what DNS returns, so a poisoned/misconfigured resolver can't open a path in.
     */
    'blocked_host_suffixes' => [
        '.localhost',
        '.local',
        '.internal',
        '.intra',
    ],

    /*
     * Individual addresses to block — the cloud instance-metadata endpoints across
     * providers (AWS/GCP IMDS, Alibaba, AWS IPv6).
     */
    'blocked_ips' => [
        '169.254.169.254', // AWS/GCP/Azure/DigitalOcean/OpenStack IMDS
        '100.100.100.200', // Alibaba Cloud
        '192.0.0.192',     // Oracle Cloud
        'fd00:ec2::254',   // AWS IMDSv2 over IPv6
    ],

    /*
     * CIDR ranges to block: Symfony's private-subnet set (loopback, RFC 1918,
     * link-local, unique-local, ULA) plus IPv4-mapped IPv6, CGNAT, and the
     * documentation/benchmark/multicast ranges an attacker could otherwise abuse.
     */
    'blocked_cidrs' => [
        ...IpUtils::PRIVATE_SUBNETS,
        '100.64.0.0/10',   // CGNAT (RFC 6598)
        '192.0.2.0/24',    // TEST-NET-1
        '198.18.0.0/15',   // benchmarking
        '198.51.100.0/24', // TEST-NET-2
        '203.0.113.0/24',  // TEST-NET-3
        '224.0.0.0/4',     // IPv4 multicast
        '2001:db8::/32',   // IPv6 documentation
        'ff00::/8',        // IPv6 multicast

        // IPv6 transition forms that embed IPv4 — Symfony's PRIVATE_SUBNETS omitted
        // these (CVE-2026-48736), letting e.g. `2002:7f00:1::` (6to4 of 127.0.0.1)
        // slip past a bitwise CIDR check. Block the whole prefixes wholesale; the
        // guard ALSO extracts and re-checks the embedded IPv4 as defence in depth.
        '::ffff:0:0/96',   // IPv4-mapped
        '::/96',           // IPv4-compatible (deprecated)
        '2002::/16',       // 6to4
        '2001::/32',       // Teredo
        '64:ff9b::/96',    // NAT64 well-known prefix
        '64:ff9b:1::/48',  // NAT64 local-use prefix
    ],
];
