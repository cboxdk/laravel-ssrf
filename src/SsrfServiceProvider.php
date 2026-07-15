<?php

declare(strict_types=1);

namespace Cbox\Ssrf;

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Illuminate\Container\Container;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;

final class SsrfServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ssrf.php', 'ssrf');

        $this->app->singleton(Resolver::class, SystemResolver::class);

        $this->app->singleton(GuardPolicy::class, function (): GuardPolicy {
            $config = config('ssrf', []);

            return GuardPolicy::fromConfig(is_array($config) ? $config : []);
        });

        $this->app->singleton(UrlGuard::class, Guard::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/ssrf.php' => $this->app->configPath('ssrf.php')], 'ssrf-config');

        $this->registerHttpMacro();
    }

    /**
     * `Http::ssrf($url)` returns a PendingRequest that has already validated $url
     * and is pinned to its resolved addresses with redirects disabled. Use it
     * exactly like the normal client: `Http::ssrf($url)->get($url)`.
     *
     * Per-call scheme/credential overrides mirror {@see UrlGuard::assertSafe()},
     * so a single client serves several sinks:
     * `Http::ssrf($repo, ['https', 'ssh'], allowCredentials: true)`.
     */
    private function registerHttpMacro(): void
    {
        if (Http::hasMacro('ssrf')) {
            return;
        }

        Http::macro('ssrf', function (string $url, ?array $allowedSchemes = null, bool $allowCredentials = false): PendingRequest {
            // Normalize to a list<string> (the guard lowercases); a caller passing
            // non-strings is a bug, so drop them rather than trust the shape.
            $schemes = $allowedSchemes === null
                ? null
                : array_values(array_filter($allowedSchemes, is_string(...)));

            // Resolve from the active container at call time (not a captured one),
            // so the macro survives Laravel/Testbench container rebuilds.
            $guard = Container::getInstance()->make(UrlGuard::class);
            $guard->assertSafe($url, $schemes, $allowCredentials);

            /** @var Factory $this */
            return $this->withOptions($guard->pinnedOptions($url, $schemes, $allowCredentials));
        });
    }
}
