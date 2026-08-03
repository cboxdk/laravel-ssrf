<?php

declare(strict_types=1);

use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Support\Facades\Http;
use Psr\Http\Message\RequestInterface;

beforeEach(function (): void {
    $this->fakeSsrfDns([
        'good.test' => ['93.184.216.34'],
        'evil.test' => ['10.1.2.3'],
        'dual.test' => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'],
    ]);
});

/**
 * Capture the Guzzle options as they reach the handler. Pushed AFTER the macro's own
 * middleware, so it sits inside it and observes what the guard actually applied.
 *
 * @param  array<string, mixed>|null  $captured
 */
function captureOptions(?array &$captured): Closure
{
    return function (callable $handler) use (&$captured): Closure {
        return function (RequestInterface $request, array $options) use ($handler, &$captured) {
            $captured = $options;

            return $handler($request, $options);
        };
    };
}

it('guards the URL passed to get(), with no URL given to the macro', function (): void {
    Http::fake(['good.test/*' => Http::response(['ok' => true])]);

    $response = Http::ssrf()->get('https://good.test/hook');

    expect($response->json('ok'))->toBeTrue();
});

it('refuses an unsafe URL at send time when the macro was given none', function (): void {
    Http::fake();

    // The whole point of the lazy form: nothing was validated up front, so the
    // rejection has to come from the URL actually being sent.
    expect(fn () => Http::ssrf()->get('https://evil.test/hook'))
        ->toThrow(BlockedUrl::class, 'non-public address');
});

it('pins the URL passed to get(), not the one passed to the macro', function (): void {
    // THE FOOTGUN. Before this release the two URLs were independent: the macro
    // validated and pinned the first while the client fetched the second. It failed
    // closed only by accident of on_stats, and only when pinning was enabled at all.
    Http::fake();

    expect(fn () => Http::ssrf('https://good.test/hook')->get('https://evil.test/hook'))
        ->toThrow(BlockedUrl::class, 'non-public address');
});

it('still validates the fetched URL when DNS pinning is off', function (): void {
    // With pin_dns off, pinnedOptions() returns no on_stats and no curl options — so
    // before this release NOTHING checked the URL that was actually fetched. Delete the
    // pinnedOptions() call in GuardRequestMiddleware and this test fails.
    $this->withSsrfConfig(['pin_dns' => false]);

    Http::fake();

    expect(fn () => Http::ssrf('https://good.test/hook')->get('https://evil.test/hook'))
        ->toThrow(BlockedUrl::class, 'non-public address');
});

it('applies the resolve pin and disables redirects for the sent URL', function (): void {
    Http::fake(['dual.test/*' => Http::response('ok')]);

    $captured = null;
    Http::ssrf()->withMiddleware(captureOptions($captured))->get('https://dual.test/hook');

    expect($captured)->toBeArray()
        ->and($captured['allow_redirects'])->toBeFalse()
        ->and($captured)->toHaveKey('on_stats');

    if (defined('CURLOPT_RESOLVE')) {
        // One entry, both families — the v1.1.1 fix, now derived from the sent URL.
        expect($captured['curl'][CURLOPT_RESOLVE])->toBe(
            ['dual.test:443:93.184.216.34,[2606:2800:220:1:248:1893:25c8:1946]'],
        );
    }
});

it('honours per-call scheme and credential overrides on the sent URL', function (): void {
    Http::fake(['git.test/*' => Http::response('ok')]);
    $this->fakeSsrfDns(['git.test' => ['93.184.216.34']]);

    // Default policy refuses both the ssh scheme and embedded credentials...
    expect(fn () => Http::ssrf()->get('ssh://user:token@git.test/acme/web.git'))
        ->toThrow(BlockedUrl::class);

    // ...but a git sink may opt into them for its own calls.
    $response = Http::ssrf(allowedSchemes: ['https', 'ssh'], allowCredentials: true)
        ->get('https://user:token@git.test/acme/web.git');

    expect($response->successful())->toBeTrue();
});

it('keeps the v1.1 two-argument form working and still fails fast', function (): void {
    Http::fake(['good.test/*' => Http::response(['ok' => true])]);

    // Backwards compatible: the documented v1.1 call still behaves as it did.
    $response = Http::ssrf('https://good.test/hook')->get('https://good.test/hook');
    expect($response->json('ok'))->toBeTrue();

    // And passing a URL still rejects it before any request object is built.
    expect(fn () => Http::ssrf('https://evil.test/hook'))->toThrow(BlockedUrl::class);
});
