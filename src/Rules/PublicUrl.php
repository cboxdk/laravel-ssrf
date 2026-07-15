<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Rules;

use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * Validation rule: the field must be a URL that is safe to fetch server-side
 * (public unicast host, allowed scheme, no credentials). Use it on any
 * user-supplied URL the application will later request — webhook endpoints,
 * avatar/import URLs, connection callback URLs.
 *
 *   $request->validate(['url' => ['required', new PublicUrl]]);
 *
 * Per-field scheme/credential rules mirror {@see UrlGuard::assertSafe()}: pass a
 * scheme allow-list and/or permit embedded credentials for the field (e.g. a git
 * URL that carries a deploy token over `https`/`ssh`).
 *
 *   new PublicUrl(allowedSchemes: ['https', 'ssh'], allowCredentials: true)
 */
final class PublicUrl implements ValidationRule
{
    /**
     * @param  list<string>|null  $allowedSchemes
     */
    public function __construct(
        private readonly ?array $allowedSchemes = null,
        private readonly bool $allowCredentials = false,
        private readonly ?UrlGuard $guard = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value)) {
            $fail('The :attribute must be a string URL.')->translate();

            return;
        }

        $guard = $this->guard ?? app(UrlGuard::class);

        try {
            $guard->assertSafe($value, $this->allowedSchemes, $this->allowCredentials);
        } catch (BlockedUrl) {
            // Deliberately generic: don't reveal which internal addresses the
            // host resolved to.
            $fail('The :attribute must be a public URL.')->translate();
        }
    }
}
