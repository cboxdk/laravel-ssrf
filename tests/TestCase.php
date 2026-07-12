<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Tests;

use Cbox\Ssrf\SsrfServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [SsrfServiceProvider::class];
    }
}
