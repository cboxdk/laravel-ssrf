<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Http;

use Cbox\Ssrf\Contracts\UrlGuard;
use Closure;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Container\Container;
use Psr\Http\Message\RequestInterface;

/**
 * The handler {@see GuardRequestMiddleware} wraps around the next one in Guzzle's
 * stack. It validates and pins the URI of the request actually being sent, then hands
 * the amended options on.
 *
 * A real invokable object rather than a closure, so the option array and the next
 * handler carry their value types into the analyser — which a closure's docblock in
 * this position does not.
 */
class GuardedHandler
{
    /** @var Closure(RequestInterface, array<string, mixed>): PromiseInterface */
    private readonly Closure $next;

    /**
     * @param  callable(RequestInterface, array<string, mixed>): PromiseInterface  $next
     * @param  list<string>|null  $allowedSchemes
     */
    public function __construct(
        callable $next,
        private readonly ?array $allowedSchemes = null,
        private readonly bool $allowCredentials = false,
    ) {
        $this->next = $next(...);
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        // pinnedOptions() re-runs the whole inspection — scheme, embedded credentials,
        // blocked hosts, and every resolved address — so this is the validation as much
        // as the pin, and it happens in EVERY configuration, including the ones where
        // there is no pin to apply (enforcement off, or DNS pinning disabled).
        $pinned = Container::getInstance()->make(UrlGuard::class)->pinnedOptions(
            (string) $request->getUri(),
            $this->allowedSchemes,
            $this->allowCredentials,
        );

        foreach (['curl', 'on_stats'] as $key) {
            if (! array_key_exists($key, $pinned)) {
                continue;
            }

            // Merge rather than overwrite, so a caller's own curl options survive; the
            // keys the guard owns still win.
            $existing = $options[$key] ?? null;
            $options[$key] = is_array($existing) && is_array($pinned[$key])
                ? array_replace($existing, $pinned[$key])
                : $pinned[$key];
        }

        return ($this->next)($request, $options);
    }
}
