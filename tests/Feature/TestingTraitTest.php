<?php

declare(strict_types=1);

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Testing\FakeResolver;

it('re-applies DNS and config after the guard has ALREADY been resolved', function (): void {
    // The guard and its policy are container singletons. A test that resolves the guard
    // before changing DNS or config would otherwise keep the stale one and quietly
    // assert nothing — which is the whole reason the trait drops them for you.
    //
    // So resolve FIRST, then change things. Delete the forgetInstance() calls in
    // InteractsWithSsrf::refreshSsrfGuard() and every expectation below the first fails.
    $this->fakeSsrfDns(['host.test' => ['93.184.216.34']]);

    expect($this->ssrfGuard()->isSafe('https://host.test'))->toBeTrue();

    // Same hostname, now answering with a private address — a rebind, in effect.
    $this->fakeSsrfDns(['host.test' => ['10.0.0.5']]);

    expect($this->ssrfGuard()->isSafe('https://host.test'))->toBeFalse();

    // And a config change must reach an already-built policy.
    $this->withSsrfConfig(['enforce' => false]);

    expect($this->ssrfGuard()->isSafe('https://host.test'))->toBeTrue();
});

it('binds the returned FakeResolver as the container Resolver', function (): void {
    $resolver = $this->fakeSsrfDns(['host.test' => ['93.184.216.34']]);

    expect($resolver)->toBeInstanceOf(FakeResolver::class)
        ->and(app(Resolver::class))->toBe($resolver)
        ->and($resolver->resolve('host.test'))->toBe(['93.184.216.34']);
});
