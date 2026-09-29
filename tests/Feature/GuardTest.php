<?php

declare(strict_types=1);

use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Cbox\Ssrf\Guard;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\TransferStats;

/**
 * The guard, with DNS answers fixed so IP-based checks are deterministic.
 *
 * A thin wrapper over the package's own `InteractsWithSsrf` trait rather than a
 * hand-rolled `new Guard(...)`: if the shipped trait is awkward for our suite it is
 * awkward for a consumer's, and we would rather find that out here.
 *
 * @param  array<string, list<string>>  $dns
 */
function guard(array $dns = []): UrlGuard
{
    test()->fakeSsrfDns($dns);

    return test()->ssrfGuard();
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

it('pins every validated address in ONE resolve entry, not one entry each', function (): void {
    // The bug this covers: curl treats a second CURLOPT_RESOLVE entry for the same
    // host:port as a REPLACEMENT, not an addition. Emitting one entry per address
    // therefore pinned only whichever sorted last and silently dropped the rest — and
    // for a dual-stack host whose AAAA sorts last (accounts.google.com does), that meant
    // every request was pinned to IPv6 alone. On a machine with no IPv6 route, every
    // guarded call then failed to connect, with no fallback to the IPv4 address that had
    // been validated moments earlier.
    //
    // Nothing in the code looked wrong: DNS resolved, both addresses were checked, the
    // pin looked complete. It died at connect time with a transport error naming neither
    // the pin nor the protocol, and it flipped with the environment — so it presented as
    // "works on my machine".
    $options = guard(['dual.test' => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']])
        ->pinnedOptions('https://dual.test/hook');

    if (! defined('CURLOPT_RESOLVE')) {
        expect(true)->toBeTrue();

        return;
    }

    expect($options['curl'][CURLOPT_RESOLVE])->toHaveCount(1)
        // curl's documented format: host:port:addr[,addr]... IPv6 bracketed, because a
        // bare one is ambiguous against the colons the format itself uses.
        ->and($options['curl'][CURLOPT_RESOLVE][0])
        ->toBe('dual.test:443:93.184.216.34,[2606:2800:220:1:248:1893:25c8:1946]');
});

it('pins the host as written in the URL when it ends in a dot', function (): void {
    // The bug this covers: the guard validates the normalized host (`example.test.` →
    // `example.test`) and pinned only that name, but curl matches a resolve entry
    // against the host AS WRITTEN in the URL. The pin was silently ignored for
    // `https://dual.test./`, curl did its own DNS lookup, and the rebinding window the
    // pin exists to close was open again — on_stats only fires after the request went.
    $options = guard(['dual.test' => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']])
        ->pinnedOptions('https://Dual.TEST./hook');

    if (! defined('CURLOPT_RESOLVE')) {
        expect(true)->toBeTrue();

        return;
    }

    // Both names, each carrying the full address list: the written form for curl as it
    // behaves today, the normalized form for one that normalizes before matching.
    expect($options['curl'][CURLOPT_RESOLVE])->toBe([
        'dual.test:443:93.184.216.34,[2606:2800:220:1:248:1893:25c8:1946]',
        'dual.test.:443:93.184.216.34,[2606:2800:220:1:248:1893:25c8:1946]',
    ]);
});

it('produces a resolve pin that libcurl actually honours for a trailing-dot host', function (): void {
    // The shape test above only proves what we emit; this proves curl uses it. The
    // guard needs a public address to pass, so keep the names it pins and swap only the
    // address for a closed local port: an honoured pin then fails fast at CONNECT, while
    // an ignored one sends curl to DNS, where `.invalid` never resolves (RFC 6761).
    // Asserting the connect failure rather than "not a resolve failure" means a slow DNS
    // timeout cannot pass for a working pin.
    $options = guard(['pin-probe.invalid' => ['93.184.216.34']])
        ->pinnedOptions('http://pin-probe.invalid.:9/');

    $handle = curl_init('http://pin-probe.invalid.:9/');
    curl_setopt_array($handle, [
        CURLOPT_RESOLVE => array_map(
            static fn (string $entry): string => preg_replace('/:[^:]+$/', ':127.0.0.1', $entry) ?? $entry,
            $options['curl'][CURLOPT_RESOLVE],
        ),
        // An explicit empty proxy overrides any *_proxy environment variable, which
        // would otherwise do the lookup on curl's behalf.
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_TIMEOUT => 5,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    curl_exec($handle);

    expect(curl_errno($handle))->toBe(CURLE_COULDNT_CONNECT);
})->skip(! function_exists('curl_init'), 'requires ext-curl');

it('validates and pins an internationalized host by its punycode name', function (): void {
    // An IDN-capable curl looks up `xn--bcher-kva.test`, never `bücher.test`. The guard
    // used to resolve and pin the UTF-8 spelling, so it validated a different DNS name
    // from the one curl connected to, and the pin was ignored.
    $options = guard(['xn--bcher-kva.test' => ['93.184.216.34']])->pinnedOptions('https://Bücher.test/hook');

    if (! defined('CURLOPT_RESOLVE')) {
        expect(true)->toBeTrue();

        return;
    }

    expect($options['curl'][CURLOPT_RESOLVE])->toBe([
        'xn--bcher-kva.test:443:93.184.216.34',
        // For a curl built without IDN, which resolves the UTF-8 name as written.
        'bücher.test:443:93.184.216.34',
    ]);
})->skip(! function_exists('idn_to_ascii'), 'requires ext-intl');

it('resolves the punycode name, not the UTF-8 bytes, of an internationalized host', function (): void {
    // DNS answered for the UTF-8 bytes only: if the guard were still resolving the name
    // as written, this would pass validation for a name curl never looks up.
    expect(guard(['bücher.test' => ['93.184.216.34']])->isSafe('https://bücher.test/'))->toBeFalse()
        ->and(guard(['xn--bcher-kva.test' => ['10.0.0.5']])->isSafe('https://bücher.test/'))->toBeFalse();
})->skip(! function_exists('idn_to_ascii'), 'requires ext-intl');

it('maps with UTS 46 non-transitional processing, as curl and browsers do', function (): void {
    // Transitional processing would turn `faß` into `fass` — a different domain.
    expect(guard(['xn--fa-hia.test' => ['93.184.216.34']])->isSafe('https://faß.test/'))->toBeTrue()
        ->and(guard(['fass.test' => ['93.184.216.34']])->isSafe('https://faß.test/'))->toBeFalse();
})->skip(! function_exists('idn_to_ascii'), 'requires ext-intl');

it('blocks compatibility spellings of blocked hosts and loopback literals', function (string $url): void {
    // curl and browsers fold these to `localhost`, `metadata.google.internal` and
    // `127.0.0.1` before connecting. Compared as written they matched no block-list
    // entry and no IP literal, so redirect mode — which does no DNS lookup to fail
    // closed on — let them through.
    guard()->assertSafeRedirect($url);
})->with([
    'fullwidth localhost' => 'http://ｌｏｃａｌｈｏｓｔ/',
    'ideographic full stop' => "http://metadata.google\u{3002}internal/computeMetadata/v1/",
    'blocked suffix' => "http://db\u{FF0E}internal/",
    'fullwidth digits' => 'http://１２７.０.０.１/',
])->throws(BlockedUrl::class)->skip(! function_exists('idn_to_ascii'), 'requires ext-intl');

it('refuses a percent-encoded host', function (callable $check): void {
    // curl decodes the host before resolving it: `%6cocalhost` connects to localhost,
    // and `%61.evil.test` is looked up as `a.evil.test` — a name nothing validated.
    $check();
})->with([
    'redirect mode, blocked host' => [fn () => guard()->assertSafeRedirect('http://%6cocalhost/')],
    'fetch mode, DNS answering the encoded label' => [
        fn () => guard(['%61.evil.test' => ['93.184.216.34']])->assertSafe('http://%61.evil.test/'),
    ],
])->throws(BlockedUrl::class, 'percent-encoded host');

it('refuses a host that is not a valid internationalized name', function (): void {
    // Unmappable means we cannot know which name the client would resolve.
    guard()->assertSafeRedirect("https://a\u{200D}b.test/"); // ZWJ outside a joining context
})->throws(BlockedUrl::class, 'not a valid internationalized domain name')
    ->skip(! function_exists('idn_to_ascii'), 'requires ext-intl');

it('produces a resolve pin that libcurl actually honours for an internationalized host', function (): void {
    // Same method as the trailing-dot test: keep the pinned names, point them at a
    // closed local port, and require a connect failure rather than a DNS one.
    $options = guard(['xn--bcher-kva.invalid' => ['93.184.216.34']])
        ->pinnedOptions('http://bücher.invalid:9/');

    $handle = curl_init('http://bücher.invalid:9/');
    curl_setopt_array($handle, [
        CURLOPT_RESOLVE => array_map(
            static fn (string $entry): string => preg_replace('/:[^:]+$/', ':127.0.0.1', $entry) ?? $entry,
            $options['curl'][CURLOPT_RESOLVE],
        ),
        CURLOPT_PROXY => '',
        CURLOPT_NOPROXY => '*',
        CURLOPT_TIMEOUT => 5,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    curl_exec($handle);

    expect(curl_errno($handle))->toBe(CURLE_COULDNT_CONNECT);
})->skip(! function_exists('curl_init') || ! function_exists('idn_to_ascii'), 'requires ext-curl and ext-intl');

it('accepts a connection to ANY validated address and still rejects one outside the set', function (): void {
    // Widening the pin must not narrow what on_stats accepts afterwards, or the request
    // connects to a perfectly valid pinned address and is then rejected by our own
    // guard. This drives the callback for real rather than asserting it exists: delete
    // the in_array() check in Guard::pinnedOptions() and the last expectation fails;
    // narrow on_stats to $ips[0] and the loop fails.
    $ips = ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'];
    $options = guard(['dual.test' => $ips])->pinnedOptions('https://dual.test/hook');

    $onStats = $options['on_stats'];

    expect($onStats)->toBeCallable();

    $connectingTo = static fn (string $ip): Closure => static fn (): mixed => $onStats(new TransferStats(
        new Request('GET', 'https://dual.test/hook'),
        handlerStats: ['primary_ip' => $ip],
    ));

    foreach ($ips as $ip) {
        expect($connectingTo($ip))->not->toThrow(BlockedUrl::class);
    }

    // An address that was never validated is still refused, pin or no pin.
    expect($connectingTo('203.0.113.9'))->toThrow(BlockedUrl::class, 'not in the validated set');
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
