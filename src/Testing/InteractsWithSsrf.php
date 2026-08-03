<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Testing;

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\GuardPolicy;
use Illuminate\Container\Container;

/**
 * Test-side wiring for the guard. Compose it into your base TestCase:
 *
 *     class TestCase extends Orchestra
 *     {
 *         use InteractsWithSsrf;
 *     }
 *
 * Then fix DNS so IP-based checks are deterministic and no test touches the network:
 *
 *     $this->fakeSsrfDns(['good.test' => ['93.184.216.34']]);
 *
 *     Http::fake();
 *     expect(fn () => Http::ssrf()->get('https://bad.test'))->toThrow(BlockedUrl::class);
 *
 * The guard and its policy are container singletons built from config, so anything
 * that changes DNS or config has to drop them — that is what every helper here does
 * for you, and forgetting it is the mistake this trait exists to prevent.
 */
trait InteractsWithSsrf
{
    /**
     * Answer DNS from a fixed table for the rest of the test.
     *
     * @param  array<string, list<string>>  $dns  hostname => the addresses it resolves to
     */
    protected function fakeSsrfDns(array $dns = []): FakeResolver
    {
        $resolver = new FakeResolver($dns);

        Container::getInstance()->instance(Resolver::class, $resolver);
        $this->refreshSsrfGuard();

        return $resolver;
    }

    /**
     * Override `config('ssrf.*')` keys and rebuild the guard so they take effect.
     * Keys are given without the `ssrf.` prefix: `['enforce' => false]`.
     *
     * @param  array<string, mixed>  $overrides
     */
    protected function withSsrfConfig(array $overrides): void
    {
        foreach ($overrides as $key => $value) {
            config(['ssrf.'.$key => $value]);
        }

        $this->refreshSsrfGuard();
    }

    /**
     * The guard as the application sees it — rebuilt from current config and DNS.
     */
    protected function ssrfGuard(): UrlGuard
    {
        return Container::getInstance()->make(UrlGuard::class);
    }

    /**
     * Drop the memoised policy and guard so the next resolve picks up whatever the
     * config and the bound resolver now say.
     */
    protected function refreshSsrfGuard(): void
    {
        $container = Container::getInstance();

        $container->forgetInstance(GuardPolicy::class);
        $container->forgetInstance(UrlGuard::class);
    }
}
