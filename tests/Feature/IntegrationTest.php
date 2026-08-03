<?php

declare(strict_types=1);

use Cbox\Ssrf\Exceptions\BlockedUrl;
use Cbox\Ssrf\Guard;
use Cbox\Ssrf\Rules\PublicUrl;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

beforeEach(function (): void {
    // Deterministic DNS for the whole container, via the trait the package ships.
    $this->fakeSsrfDns([
        'good.test' => ['93.184.216.34'],
        'bad.test' => ['10.1.2.3'],
    ]);
});

it('passes the PublicUrl validation rule for a public URL', function (): void {
    $validator = Validator::make(['url' => 'https://good.test/webhook'], ['url' => [new PublicUrl]]);

    expect($validator->passes())->toBeTrue();
});

it('fails the PublicUrl validation rule for a private URL', function (): void {
    $validator = Validator::make(['url' => 'https://bad.test/webhook'], ['url' => [new PublicUrl]]);

    expect($validator->fails())->toBeTrue()
        ->and($validator->errors()->first('url'))->toContain('public URL');
});

it('exposes an Http::ssrf macro that refuses an unsafe URL before sending', function (): void {
    Http::fake();

    expect(fn () => Http::ssrf('https://bad.test/hook'))->toThrow(BlockedUrl::class);
});

it('lets the Http::ssrf macro build a pinned request for a safe URL', function (): void {
    Http::fake(['good.test/*' => Http::response(['ok' => true])]);

    $response = Http::ssrf('https://good.test/hook')->get('https://good.test/hook');

    expect($response->json('ok'))->toBeTrue();
});

it('skips DNS/IP enforcement when disabled, but still checks scheme and host', function (): void {
    // withSsrfConfig() rebuilds the policy and guard, which is the step that is easy
    // to forget by hand and silently leaves the old config in place.
    $this->withSsrfConfig(['enforce' => false]);

    $guard = $this->ssrfGuard();

    // A private host now passes (enforcement off)...
    expect($guard->isSafe('https://bad.test'))->toBeTrue();
    // ...but scheme and blocked-host checks still apply.
    expect(fn () => $guard->assertSafe('file:///etc/passwd'))->toThrow(BlockedUrl::class)
        ->and(fn () => $guard->assertSafe('http://localhost'))->toThrow(BlockedUrl::class);
});
