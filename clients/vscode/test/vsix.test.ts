/**
 * The package this repository produces. R8.3, the half that is ours.
 *
 * What can be checked here is that the file is a well-formed zip holding the
 * parts an installer looks for. **What cannot be checked here is that VS Code
 * installs it**, because there is no VS Code to install it with — the zip is
 * read back with Python's own `zipfile`, which is a second reader rather than
 * this one's, and that is as far as the evidence goes.
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { NEEDS_PUBLISHER, build, contents } from '../scripts/vsix.js';
import { scratch } from './support.js';

/** The extension's own directory, from the compiled test. */
const ROOT = path.resolve(__dirname, '../..');

/** Whether unzip is on hand to extract the package independently. */
function unzip(): boolean {
    try {
        execFileSync('unzip', ['-v'], { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

/** Whether a Python is on hand to read the zip back independently. */
function python(): string | undefined {
    for (const candidate of ['python3', 'python']) {
        try {
            execFileSync(candidate, ['--version'], { stdio: 'ignore' });
            return candidate;
        } catch {
            continue;
        }
    }
    return undefined;
}

describe('the vsix', () => {
    const dir = scratch('vsix');

    after(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('will not invent a publisher id', () => {
        // Packaging is ours; the identity a package is published under is not.
        assert.match(NEEDS_PUBLISHER, /does not have one/);
        assert.match(NEEDS_PUBLISHER, /--publisher/);
        assert.ok(!NEEDS_PUBLISHER.includes('vsce publish'));
    });

    it('holds the parts an installer looks for, and nothing from the toolchain', () => {
        const names = contents(ROOT, 'somebody').map((part) => part.name);
        assert.ok(names.includes('[Content_Types].xml'));
        assert.ok(names.includes('extension.vsixmanifest'));
        assert.ok(names.includes('extension/package.json'));
        assert.ok(names.includes('extension/dist/src/extension.js'));
        assert.ok(names.some((name) => name.startsWith('extension/LICENSE')));
        assert.ok(names.includes('extension/README.md'));
        assert.ok(names.includes('extension/icon.png'));

        for (const name of names) {
            assert.ok(!name.includes('node_modules'), name);
            assert.ok(!name.includes('/test/'), name);
            assert.ok(!name.includes('/scripts/'), name);
            assert.ok(!name.endsWith('.ts'), name);
            assert.ok(!name.endsWith('.map'), name);
        }
    });

    it('injects the publisher rather than committing one', () => {
        const parts = contents(ROOT, 'somebody');
        const shipped = parts.find((part) => part.name === 'extension/package.json');
        assert.ok(shipped);
        assert.equal(JSON.parse(shipped.bytes.toString()).publisher, 'somebody');

        const committed = JSON.parse(
            fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'),
        ) as Record<string, unknown>;
        assert.equal(committed.publisher, undefined, 'a publisher id was committed');
    });

    it('names a content type for every part, which OPC requires', () => {
        const parts = contents(ROOT, 'somebody');
        const types = parts.find((part) => part.name === '[Content_Types].xml');
        assert.ok(types);
        const declared = new Set(
            [...types.bytes.toString().matchAll(/Extension="([^"]+)"/g)].map((found) =>
                found[1]?.toLowerCase(),
            ),
        );
        const overridden = new Set(
            [...types.bytes.toString().matchAll(/PartName="\/([^"]+)"/g)].map((found) => found[1]),
        );
        for (const part of parts) {
            // The content-type map is not itself a part, and names no type for
            // itself.
            if (part.name === '[Content_Types].xml') {
                continue;
            }
            const dot = path.basename(part.name).lastIndexOf('.');
            if (dot <= 0) {
                assert.ok(overridden.has(part.name), part.name);
                continue;
            }
            const extension = part.name.slice(part.name.lastIndexOf('.') + 1).toLowerCase();
            assert.ok(declared.has(extension), `${part.name} has no content type`);
        }
    });

    it('points a marketplace at the icon it carries', () => {
        // The field alone is not the icon: an installer reads the asset, so
        // both the element and the asset row have to be there.
        const manifest = contents(ROOT, 'somebody')
            .find((part) => part.name === 'extension.vsixmanifest')
            ?.bytes.toString();
        assert.ok(manifest);
        const icon = (
            JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')) as {
                icon?: string;
            }
        ).icon;
        assert.ok(icon, 'the manifest names no icon');
        assert.ok(manifest.includes(`<Icon>extension/${icon}</Icon>`));
        assert.match(
            manifest,
            new RegExp(
                `<Asset Type="Microsoft\\.VisualStudio\\.Services\\.Icons\\.Default" Path="extension/${icon.replace(/[.]/g, '\\.')}"`,
            ),
        );
    });

    it('declares the platform it was packaged for, and none when it was not', () => {
        const of = (target?: string) =>
            contents(ROOT, 'somebody', target)
                .find((part) => part.name === 'extension.vsixmanifest')
                ?.bytes.toString() ?? '';
        assert.match(of('darwin-arm64'), /<Identity [^>]*TargetPlatform="darwin-arm64"/);
        assert.ok(!of().includes('TargetPlatform'), 'the fallback package named a platform');
    });

    it(
        'extracts the bundled binary executable',
        {
            skip:
                process.platform === 'win32'
                    ? 'no unix modes'
                    : unzip()
                      ? false
                      : 'no unzip',
        },
        () => {
            assert.ok(!fs.existsSync(path.join(ROOT, 'bin')), 'bin/ is in the way');
            try {
                fs.mkdirSync(path.join(ROOT, 'bin', 'darwin-arm64'), { recursive: true });
                fs.writeFileSync(path.join(ROOT, 'bin', 'darwin-arm64', 'rpf'), '#!/bin/sh\n');
                const at = build(ROOT, 'somebody', path.join(dir, 'rpf-exec.vsix'));
                const into = path.join(dir, 'unpacked');
                fs.rmSync(into, { recursive: true, force: true });
                fs.mkdirSync(into, { recursive: true });
                execFileSync('unzip', ['-q', at, '-d', into]);
                // What locate.ts gates every candidate on; a zip entry made by
                // MS-DOS extracts as 0o644 and is silently skipped.
                fs.accessSync(path.join(into, 'extension/bin/darwin-arm64/rpf'), fs.constants.X_OK);
            } finally {
                fs.rmSync(path.join(ROOT, 'bin'), { recursive: true, force: true });
            }
        },
    );

    it('writes a zip a second reader agrees is a zip', { skip: python() ? false : 'no python' } , () => {
        const at = build(ROOT, 'somebody', path.join(dir, 'rpf-test.vsix'));
        assert.ok(fs.statSync(at).size > 0);

        const read = execFileSync(
            python() as string,
            [
                '-c',
                [
                    'import json,sys,zipfile',
                    'z=zipfile.ZipFile(sys.argv[1])',
                    'assert z.testzip() is None',
                    'print(json.dumps({',
                    '  "names": z.namelist(),',
                    '  "manifest": z.read("extension.vsixmanifest").decode(),',
                    '  "package": json.loads(z.read("extension/package.json")),',
                    '}))',
                ].join('\n'),
                at,
            ],
            { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
        );
        const inside = JSON.parse(read) as {
            names: string[];
            manifest: string;
            package: { name: string; publisher: string; main: string };
        };

        assert.ok(inside.names.includes('extension.vsixmanifest'));
        assert.ok(inside.names.includes('extension/dist/src/extension.js'));
        assert.equal(inside.package.publisher, 'somebody');
        assert.match(inside.manifest, /Publisher="somebody"/);
        assert.match(inside.manifest, /Microsoft\.VisualStudio\.Code\.Engine/);
        assert.match(inside.manifest, /Microsoft\.VisualStudio\.Code\.Manifest/);
        assert.ok(
            inside.names.includes(`extension/${inside.package.main.replace('./', '')}`),
            `the manifest points at ${inside.package.main}, which is not in the package`,
        );
    });
});
