#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Generates a CycloneDX 1.5 SBOM (JSON) from composer.lock — self-contained, no
 * plugins or network. Output is deterministic (components sorted, serial number
 * derived from content) so a committed SBOM only changes when dependencies do.
 *
 *   composer sbom              # production dependencies -> sbom.json
 *   php bin/generate-sbom.php --dev --output=sbom-dev.json
 */
$root = dirname(__DIR__);
$lock = json_decode((string) file_get_contents($root.'/composer.lock'), true, 512, JSON_THROW_ON_ERROR);
$self = json_decode((string) file_get_contents($root.'/composer.json'), true, 512, JSON_THROW_ON_ERROR);

$includeDev = in_array('--dev', $argv, true);
$output = $root.'/sbom.json';
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--output=')) {
        $output = substr($arg, strlen('--output='));
    }
}

$packages = $lock['packages'] ?? [];
if ($includeDev) {
    $packages = array_merge($packages, $lock['packages-dev'] ?? []);
}

usort($packages, static fn (array $a, array $b): int => strcmp((string) $a['name'], (string) $b['name']));

$components = array_map('componentFor', $packages);

$serial = 'urn:uuid:'.deterministicUuid(implode('|', array_column($components, 'purl')));

$bom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.5',
    'serialNumber' => $serial,
    'version' => 1,
    'metadata' => [
        'tools' => [[
            'vendor' => 'cboxdk',
            'name' => 'laravel-id-sbom',
            'version' => '1.0.0',
        ]],
        'component' => [
            'type' => 'library',
            'bom-ref' => (string) $self['name'],
            'name' => (string) $self['name'],
            'purl' => 'pkg:composer/'.$self['name'],
        ],
    ],
    'components' => $components,
];

file_put_contents(
    $output,
    json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n",
);

printf("Wrote %s: %d components (%s).\n", $output, count($components), $includeDev ? 'production + dev' : 'production');

/**
 * @param  array<string, mixed>  $package
 * @return array<string, mixed>
 */
function componentFor(array $package): array
{
    $name = (string) $package['name'];
    $version = (string) ($package['version'] ?? '0.0.0');
    $purl = 'pkg:composer/'.$name.'@'.$version;
    [$group, $short] = array_pad(explode('/', $name, 2), 2, $name);

    $component = [
        'type' => 'library',
        'bom-ref' => $purl,
        'group' => $group,
        'name' => $short,
        'version' => $version,
        'purl' => $purl,
    ];

    if (isset($package['description']) && is_string($package['description'])) {
        $component['description'] = $package['description'];
    }

    $licenses = licenseEntries($package['license'] ?? []);
    if ($licenses !== []) {
        $component['licenses'] = $licenses;
    }

    $shasum = $package['dist']['shasum'] ?? '';
    if (is_string($shasum) && $shasum !== '') {
        $component['hashes'] = [['alg' => 'SHA-1', 'content' => $shasum]];
    }

    return $component;
}

/**
 * @param  list<string>|string  $license
 * @return list<array<string, mixed>>
 */
function licenseEntries(array|string $license): array
{
    $items = array_values(array_filter(is_array($license) ? $license : [$license], 'is_string'));

    if ($items === []) {
        return [];
    }

    // A single declared license -> SPDX id; multiple -> an SPDX expression.
    if (count($items) === 1) {
        return [['license' => ['id' => $items[0]]]];
    }

    return [['expression' => '('.implode(' OR ', $items).')']];
}

function deterministicUuid(string $seed): string
{
    $hash = md5('cboxdk/laravel-id:'.$seed);

    return sprintf(
        '%s-%s-4%s-%s-%s',
        substr($hash, 0, 8),
        substr($hash, 8, 4),
        substr($hash, 13, 3),
        dechex((hexdec($hash[16]) & 0x3) | 0x8).substr($hash, 17, 3),
        substr($hash, 20, 12),
    );
}
