<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Tests;

use Cbox\Ssrf\SsrfServiceProvider;
use Cbox\Ssrf\Testing\InteractsWithSsrf;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    // The package's own suite goes through the trait it ships, so the trait is
    // exercised by every test rather than merely documented.
    use InteractsWithSsrf;

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [SsrfServiceProvider::class];
    }
}
