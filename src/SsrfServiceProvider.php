<?php

declare(strict_types=1);

namespace Cbox\Ssrf;

use Cbox\Ssrf\Contracts\Resolver;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Http\GuardRequestMiddleware;
use Illuminate\Container\Container;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\ServiceProvider;

class SsrfServiceProvider extends ServiceProvider
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
     * `Http::ssrf()` returns a PendingRequest that validates and pins whatever URL it
     * is finally sent to, with redirects disabled:
     *
     *     Http::ssrf()->get($url);
     *
     * The URL is guarded at send time by {@see GuardRequestMiddleware}, so the URL that
     * is validated is by construction the URL that is fetched. `Http::ssrf($url)` still
     * works and additionally fails fast, before a request object is built — useful when
     * a caller wants the rejection at the point the URL is chosen rather than at send.
     *
     * Per-call scheme/credential overrides mirror {@see UrlGuard::assertSafe()}, so a
     * single client serves several sinks:
     * `Http::ssrf(allowedSchemes: ['https', 'ssh'], allowCredentials: true)`.
     */
    private function registerHttpMacro(): void
    {
        if (Http::hasMacro('ssrf')) {
            return;
        }

        Http::macro('ssrf', function (?string $url = null, ?array $allowedSchemes = null, bool $allowCredentials = false): PendingRequest {
            // Normalize to a list<string> (the guard lowercases); a caller passing
            // non-strings is a bug, so drop them rather than trust the shape.
            $schemes = $allowedSchemes === null
                ? null
                : array_values(array_filter($allowedSchemes, is_string(...)));

            if ($url !== null) {
                // Resolve from the active container at call time (not a captured one),
                // so the macro survives Laravel/Testbench container rebuilds.
                Container::getInstance()->make(UrlGuard::class)
                    ->assertSafe($url, $schemes, $allowCredentials);
            }

            /** @var Factory $this */
            return $this
                // Redirects are refused for every request this client makes, whatever
                // the URL — a 30x to a fresh host is another SSRF path. Set eagerly
                // because Guzzle's redirect middleware sits OUTSIDE caller middleware
                // and has already read its options by the time the guard runs.
                ->withOptions(['allow_redirects' => false])
                ->withMiddleware(new GuardRequestMiddleware($schemes, $allowCredentials));
        });
    }
}
