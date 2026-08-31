/**
 * Handing an out-of-scope asset to another tool, and taking it back. R7.5.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { Daemon } from '../src/core/daemon.js';
import { DaemonError, EXIT } from '../src/core/errors.js';
import { HandOff, isPassthrough, scratchFor } from '../src/core/handoff.js';
import { ArchiveSession } from '../src/core/session.js';
import { SKIP, binary, packArchive, resourceBytes, scratch } from './support.js';

describe('naming a handed-off file', () => {
    it('knows which entries this tool does not claim to understand', () => {
        for (const passed of ['art.yft', 'x64/a.YTD', 'deep/one.dds']) {
            assert.equal(isPassthrough(passed), true, passed);
        }
        for (const kept of ['data/handling.meta', 'readme.txt', 'noextension', '.hidden']) {
            assert.equal(isPassthrough(kept), false, kept);
        }
    });

    it('invents a host name rather than reusing the entry\'s', () => {
        // DR-013 and DR-015 decide what an archive name may be as a file on a
        // host, and they decide it in rpf-core. A scratch name nobody has to
        // check costs less than that rule written twice.
        const troublesome = ['x64\\evil.txt.yft', 'aux.ytd', 'trailing .ytd', 'a/b/c.ytd'];
        for (const inside of troublesome) {
            const at = scratchFor('/scratch', '/tmp/a.rpf', inside);
            const name = path.basename(at);
            assert.equal(path.dirname(path.dirname(at)), '/scratch');
            assert.ok(!name.includes('\\'), name);
            assert.ok(!name.includes('/'), name);
            assert.match(name, /^[0-9a-f]{12}-[A-Za-z0-9._-]+$/, name);
        }
    });

    it('gives two entries with one basename two files', () => {
        const one = scratchFor('/s', '/tmp/a.rpf', 'x64/art.yft');
        const two = scratchFor('/s', '/tmp/a.rpf', 'other/art.yft');
        assert.notEqual(one, two);
        assert.equal(one, scratchFor('/s', '/tmp/a.rpf', 'x64/art.yft'));
    });
});

describe('handing an entry over and taking it back', { skip: SKIP }, () => {
    const dir = scratch('handoff');
    const running: Daemon[] = [];
    const handoffs: HandOff[] = [];

    after(async () => {
        for (const handoff of handoffs) {
            handoff.dispose();
        }
        await Promise.all(running.map((daemon) => daemon.dispose()));
        fs.rmSync(dir, { recursive: true, force: true });
    });

    async function open(name: string): Promise<{ session: ArchiveSession; handoff: HandOff }> {
        const archive = await packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'art.yft', bytes: resourceBytes(), class: 'resource', storage: 'stored' },
                { path: 'data/handling.meta', bytes: Buffer.from('<handling/>') },
            ],
        });
        const daemon = Daemon.start({ binary: binary() });
        running.push(daemon);
        const session = await ArchiveSession.open(daemon, archive);
        const handoff = new HandOff(session, { directory: path.join(dir, `${name}-scratch`) });
        handoffs.push(handoff);
        return { session, handoff };
    }

    it('writes the entry out as the bytes another tool expects', async () => {
        // A resource's bytes here are what `rpf cat` and `rpf extract` write:
        // the RSC7 header included, which is what the file is outside the
        // archive.
        const { handoff } = await open('out');
        const handed = await handoff.begin('art.yft');
        assert.deepEqual(fs.readFileSync(handed.file), resourceBytes());
        assert.deepEqual(
            handoff.outstanding().map((one) => one.inside),
            ['art.yft'],
        );
    });

    it('buffers a change rather than writing it through', async () => {
        // R7.3's rule stands for a hand-off too: the archive is written by one
        // explicit act, and a file watcher firing is not one.
        const { session, handoff } = await open('back');
        const before = fs.readFileSync(session.path);
        const handed = await handoff.begin('art.yft');

        const changed = Buffer.concat([resourceBytes(), Buffer.alloc(0)]);
        changed.writeUInt32LE(163, 4);
        fs.writeFileSync(handed.file, changed);

        const event = await handoff.reimport('art.yft');
        assert.ok(event && 'len' in event, `re-import failed: ${JSON.stringify(event)}`);
        assert.equal(session.state, 'dirty');
        assert.deepEqual(session.dirtyPaths(), ['art.yft']);
        assert.deepEqual(fs.readFileSync(session.path), before, 'the archive was written through');

        await session.save();
        assert.deepEqual(await session.read('art.yft'), changed);
    });

    it('does not make the archive dirty when the file comes back unchanged', async () => {
        const { session, handoff } = await open('touched');
        const handed = await handoff.begin('art.yft');
        fs.writeFileSync(handed.file, fs.readFileSync(handed.file));
        assert.equal(await handoff.reimport('art.yft'), undefined);
        assert.equal(session.state, 'clean');
    });

    it('carries a re-import through to the save the daemon refuses, rather than losing it', async () => {
        // A converter that dropped the RSC7 header would otherwise leave the
        // user with an edit that vanished. DR-046 moved the refusal itself
        // from the write to the save, so the re-import now takes the payload
        // — it is not swallowed, it is buffered — and it is the save that
        // the daemon refuses once it cannot fill the row from it.
        const { session, handoff } = await open('refused');
        const handed = await handoff.begin('art.yft');
        fs.writeFileSync(handed.file, Buffer.from('not a resource'));
        const event = await handoff.reimport('art.yft');
        assert.ok(event && 'len' in event, `re-import lost the edit: ${JSON.stringify(event)}`);
        assert.equal(session.state, 'dirty');

        const failure = await session.save().then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.refused);
        assert.match(failure.reason, /shorter than a resource header/);
        assert.equal(session.state, 'dirty', 'a refused save must not discard the edit it refused');
    });

    it('notices a file another tool wrote, without being asked', async () => {
        const { session, handoff } = await open('watched');
        const handed = await handoff.begin('art.yft');
        const imported = new Promise<void>((seen) => {
            handoff.onImported(() => seen());
        });
        const changed = resourceBytes();
        changed.writeUInt32LE(164, 4);
        fs.writeFileSync(handed.file, changed);
        await imported;
        assert.deepEqual(session.dirtyPaths(), ['art.yft']);
    });

    it('notices a change the directory watch never reported', async () => {
        // On macOS every `fs.watch` in a process shares one FSEvents stream and
        // arming another rebuilds it, so a write during the rebuild reaches
        // nobody — measured at 39 losses in 150 with four watchers already
        // armed. The directory watch is closed here to reproduce that exactly,
        // rather than by racing it.
        const { session, handoff } = await open('missed');
        const handed = await handoff.begin('art.yft');
        const watchers = (handoff as unknown as { watchers: Map<string, { close: () => void }> })
            .watchers;
        watchers.get('art.yft')?.close();
        watchers.delete('art.yft');

        const imported = new Promise<void>((seen) => {
            handoff.onImported(() => seen());
        });
        const changed = resourceBytes();
        changed.writeUInt32LE(165, 4);
        fs.writeFileSync(handed.file, changed);
        await imported;
        assert.deepEqual(session.dirtyPaths(), ['art.yft']);
    });

    it('stops watching when told, and leaves the file where it is', async () => {
        const { session, handoff } = await open('stop');
        const handed = await handoff.begin('art.yft');
        handoff.end('art.yft');
        assert.deepEqual(handoff.outstanding(), []);
        assert.equal(await handoff.reimport('art.yft'), undefined);
        assert.ok(fs.existsSync(handed.file));
        assert.equal(session.state, 'clean');
    });
});
