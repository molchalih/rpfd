import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';

import { binaryName, bundledAt, candidates, locate } from '../src/core/locate.js';
import { SKIP, binary } from './support.js';

describe('finding the binary', () => {
    it('looks where the user said first, then in the extension, then on PATH', () => {
        const looked = candidates({
            setting: '/opt/rpf',
            extensionRoot: '/ext',
            pathVariable: '/usr/local/bin:/usr/bin',
            platform: 'linux',
            arch: 'x64',
        });
        assert.deepEqual(looked, [
            { source: 'setting', at: '/opt/rpf' },
            { source: 'bundled', at: path.join('/ext', 'bin', 'linux-x64', 'rpf') },
            { source: 'path', at: path.join('/usr/local/bin', 'rpf') },
            { source: 'path', at: path.join('/usr/bin', 'rpf') },
        ]);
    });

    it('names a bundled binary by its target, because a static binary is per target', () => {
        assert.equal(binaryName('win32'), 'rpf.exe');
        assert.equal(binaryName('darwin'), 'rpf');
        assert.equal(bundledAt('/ext', 'win32', 'x64'), path.join('/ext', 'bin', 'win32-x64', 'rpf.exe'));
        assert.equal(bundledAt('/ext', 'darwin', 'arm64'), path.join('/ext', 'bin', 'darwin-arm64', 'rpf'));
    });

    it('splits PATH the way the platform does', () => {
        const windows = candidates({
            pathVariable: 'C:\\bin;C:\\other',
            platform: 'win32',
            arch: 'x64',
        });
        assert.equal(windows.length, 2);
        assert.ok(windows[0]?.at.endsWith('rpf.exe'));
    });

    it('says where it looked and what to do when there is no binary', async () => {
        const outcome = await locate({
            setting: '/nowhere/rpf',
            pathVariable: '/nowhere/else',
            probe: async () => undefined,
        });
        assert.equal(outcome.found, false);
        if (outcome.found) {
            return;
        }
        assert.equal(outcome.tried.length, 2);
        assert.match(outcome.instructions, /rpf\.binaryPath/);
        assert.match(outcome.instructions, /cargo build --release/);
        assert.match(outcome.instructions, /nowhere/);
    });

    it('declines a file that is executable and is not this tool', { skip: SKIP }, async () => {
        // A wrong binary called rpf fails later and less clearly than none, so
        // every candidate is proved by running it.
        const outcome = await locate({
            setting: '/bin/echo',
            pathVariable: path.dirname(binary()),
        });
        assert.equal(outcome.found, true);
        if (!outcome.found) {
            return;
        }
        assert.equal(outcome.source, 'path', 'the wrong binary was accepted');
        assert.equal(outcome.path, binary());
        assert.match(outcome.version, /^rpf /);
    });

    it('lets the setting win over PATH', { skip: SKIP }, async () => {
        const outcome = await locate({
            setting: binary(),
            pathVariable: '/nowhere',
        });
        assert.equal(outcome.found, true);
        if (!outcome.found) {
            return;
        }
        assert.equal(outcome.source, 'setting');
    });
});
