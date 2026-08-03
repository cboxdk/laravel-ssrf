<?php

declare(strict_types=1);

namespace Cbox\Ssrf\Tests\Fixtures;

use Cbox\Ssrf\Testing\InteractsWithSsrf;

/**
 * A composition site for {@see InteractsWithSsrf}, so the analyser actually checks it.
 *
 * PHPStan only analyses a trait where it is used. The real composition site is
 * `tests/TestCase.php`, which sits outside the analysis paths — without this fixture
 * the shipped trait would be the one piece of `src/` nothing type-checks, which is
 * precisely backwards for code consumers are told to build their test suites on.
 */
class InteractsWithSsrfFixture
{
    use InteractsWithSsrf;
}
