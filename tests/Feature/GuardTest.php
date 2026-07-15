<?php

declare(strict_types=1);

use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Cbox\Ssrf\Guard;
use Cbox\Ssrf\GuardPolicy;
use Cbox\Ssrf\Testing\FakeResolver;

/**
 * Build a Guard whose DNS answers are fixed, so IP-based checks are deterministic.
 *
 * @param  array<string, list<string>>  $dns
 */
function guard(array $dns = []): Guard
{
    return new Guard(app(GuardPolicy::class), new FakeResolver($dns));
}

it('allows a public host', function (): void {
    expect(guard(['example.test' => ['93.184.216.34']])->isSafe('https://example.test/webhook'))->toBeTrue();
});

it('blocks a host that resolves to a private (RFC 1918) address', function (): void {
    guard(['evil.test' => ['10.0.0.5']])->assertSafe('https://evil.test');
})->throws(BlockedUrl::class);

it('blocks loopback', function (): void {
    guard(['evil.test' => ['127.0.0.1']])->assertSafe('http://evil.test');
})->throws(BlockedUrl::class);

it('blocks the AWS/GCP cloud-metadata address', function (): void {
    guard(['evil.test' => ['169.254.169.254']])->assertSafe('http://evil.test/latest/meta-data/');
})->throws(BlockedUrl::class);

it('blocks an IPv4-mapped IPv6 loopback', function (): void {
    guard(['evil.test' => ['::ffff:127.0.0.1']])->assertSafe('http://evil.test');
})->throws(BlockedUrl::class);

it('blocks a CGNAT address', function (): void {
    guard(['evil.test' => ['100.64.1.1']])->assertSafe('http://evil.test');
})->throws(BlockedUrl::class);

it('blocks 6to4-encoded loopback (IPv6 transition form)', function (): void {
    // 2002:7f00:1:: is the 6to4 form of 127.0.0.1 — the Symfony CVE-2026-48736 class.
    guard(['evil.test' => ['2002:7f00:1::']])->assertSafe('http://evil.test');
})->throws(BlockedUrl::class);

it('blocks a NAT64-encoded private address', function (): void {
    // 64:ff9b::0a00:0001 embeds 10.0.0.1.
    guard(['evil.test' => ['64:ff9b::a00:1']])->assertSafe('http://evil.test');
})->throws(BlockedUrl::class);

it('blocks when any one of several resolved addresses is private', function (): void {
    // A host that returns both a public and a private A record must be refused.
    guard(['evil.test' => ['93.184.216.34', '192.168.1.1']])->assertSafe('https://evil.test');
})->throws(BlockedUrl::class);

it('refuses a non-http scheme', function (): void {
    guard()->assertSafe('file:///etc/passwd');
})->throws(BlockedUrl::class, 'scheme');

it('refuses embedded credentials', function (): void {
    guard(['example.test' => ['93.184.216.34']])->assertSafe('https://user:pass@example.test');
})->throws(BlockedUrl::class, 'credentials');

it('refuses a blocked hostname regardless of DNS', function (): void {
    guard(['localhost' => ['93.184.216.34']])->assertSafe('http://localhost');
})->throws(BlockedUrl::class);

it('refuses a blocked host suffix (.internal) even if it resolves publicly', function (): void {
    guard(['api.internal' => ['93.184.216.34']])->assertSafe('https://api.internal');
})->throws(BlockedUrl::class);

it('refuses a host that does not resolve', function (): void {
    guard()->assertSafe('https://nope.test');
})->throws(BlockedUrl::class, 'does not resolve');

it('refuses an IP literal in a private range directly', function (): void {
    guard()->assertSafe('http://192.168.0.1');
})->throws(BlockedUrl::class);

it('allows a public IP literal', function (): void {
    expect(guard()->isSafe('https://93.184.216.34'))->toBeTrue();
});

it('normalizes integer- and hex-encoded IPv4 loopback in redirect mode', function (): void {
    // Browsers accept these; the guard must too, and block them.
    expect(fn () => guard()->assertSafeRedirect('http://2130706433'))->toThrow(BlockedUrl::class)
        ->and(fn () => guard()->assertSafeRedirect('http://0x7f000001'))->toThrow(BlockedUrl::class);
});

it('allows an unresolved hostname in redirect mode (the browser resolves it)', function (): void {
    // Redirect mode does not consult DNS, so a corp-only IdP host still validates.
    guard()->assertSafeRedirect('https://idp.customer-corp.test/authorize');

    expect(true)->toBeTrue(); // reached only if no BlockedUrl was thrown
});

it('pins the connection and disables redirects for a safe URL', function (): void {
    $options = guard(['example.test' => ['93.184.216.34']])->pinnedOptions('https://example.test/hook');

    expect($options['allow_redirects'])->toBeFalse()
        ->and($options)->toHaveKey('on_stats');

    if (defined('CURLOPT_RESOLVE')) {
        expect($options['curl'][CURLOPT_RESOLVE][0])->toBe('example.test:443:93.184.216.34');
    }
});

it('resolves the UrlGuard contract from the container', function (): void {
    expect(app(UrlGuard::class))->toBeInstanceOf(Guard::class);
});

/*
 * Per-call scheme/credential overrides (v1.1): one guard, several sinks.
 */

it('accepts a per-call scheme the global policy omits (ssh for git)', function (): void {
    // Global allowed_schemes is [http, https]; ssh is refused by default…
    expect(fn () => guard(['git.test' => ['93.184.216.34']])->assertSafe('ssh://git.test/acme/web.git'))
        ->toThrow(BlockedUrl::class, 'scheme');

    // …but a git sink may opt into it per call.
    guard(['git.test' => ['93.184.216.34']])
        ->assertSafe('ssh://git.test/acme/web.git', allowedSchemes: ['https', 'ssh']);

    expect(true)->toBeTrue();
});

it('narrows schemes per call (a webhook sink refuses http)', function (): void {
    // Global policy allows http, but a webhook sink pins to https only.
    expect(guard(['hook.test' => ['93.184.216.34']])->isSafe('http://hook.test', allowedSchemes: ['https']))
        ->toBeFalse()
        ->and(guard(['hook.test' => ['93.184.216.34']])->isSafe('https://hook.test', allowedSchemes: ['https']))
        ->toBeTrue();
});

it('permits embedded credentials only when the call opts in', function (): void {
    // Default: credentials refused.
    expect(fn () => guard(['git.test' => ['93.184.216.34']])->assertSafe('https://user:token@git.test/acme/web.git'))
        ->toThrow(BlockedUrl::class, 'credentials');

    // Opt-in: a git URL carrying a deploy token is accepted…
    guard(['git.test' => ['93.184.216.34']])
        ->assertSafe('https://user:token@git.test/acme/web.git', allowedSchemes: ['https', 'ssh'], allowCredentials: true);

    expect(true)->toBeTrue();
});

it('still enforces the block-list under a per-call override', function (): void {
    // A per-call scheme/credential override must NOT relax IP/host enforcement:
    // a credentialed ssh URL to a private address is still refused.
    guard(['git.test' => ['10.0.0.5']])
        ->assertSafe('ssh://user:token@git.test/acme/web.git', allowedSchemes: ['https', 'ssh'], allowCredentials: true);
})->throws(BlockedUrl::class);

it('pins per-call for an overridden sink', function (): void {
    $options = guard(['git.test' => ['93.184.216.34']])
        ->pinnedOptions('https://user:token@git.test/acme/web.git', allowedSchemes: ['https', 'ssh'], allowCredentials: true);

    expect($options['allow_redirects'])->toBeFalse();
});
