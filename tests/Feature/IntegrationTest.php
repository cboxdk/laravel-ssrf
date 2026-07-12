<?php

declare(strict_types=1);

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Cbox\Ssrf\GuardPolicy;
use Cbox\Ssrf\Rules\PublicUrl;
use Cbox\Ssrf\Testing\FakeResolver;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;

beforeEach(function (): void {
    // Deterministic DNS for the whole container (the guard is a singleton).
    $this->app->instance(Resolver::class, new FakeResolver([
        'good.test' => ['93.184.216.34'],
        'bad.test' => ['10.1.2.3'],
    ]));
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
    config(['ssrf.enforce' => false]);
    // Rebind the policy/guard so the new config takes effect.
    $this->app->forgetInstance(GuardPolicy::class);
    $this->app->forgetInstance(UrlGuard::class);

    $guard = app(UrlGuard::class);

    // A private host now passes (enforcement off)...
    expect($guard->isSafe('https://bad.test'))->toBeTrue();
    // ...but scheme and blocked-host checks still apply.
    expect(fn () => $guard->assertSafe('file:///etc/passwd'))->toThrow(BlockedUrl::class)
        ->and(fn () => $guard->assertSafe('http://localhost'))->toThrow(BlockedUrl::class);
});
