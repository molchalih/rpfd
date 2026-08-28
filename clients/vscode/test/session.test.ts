/**
 * Buffered edits, and the one act that writes them. R7.3, R7.2's first half.
 *
 * Every case here runs against a real `rpf serve --stdio`.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { Daemon } from '../src/core/daemon.js';
import { DaemonError, EXIT, advise } from '../src/core/errors.js';
import { ArchiveSession, SessionBusy } from '../src/core/session.js';
import { SKIP, binary, incompressible, packArchive, resourceBytes, scratch } from './support.js';

describe('an archive session', { skip: SKIP }, () => {
    const dir = scratch('session');
    const running: Daemon[] = [];

    after(async () => {
        await Promise.all(running.map((daemon) => daemon.dispose()));
        fs.rmSync(dir, { recursive: true, force: true });
    });

    function start(): Daemon {
        const daemon = Daemon.start({ binary: binary() });
        running.push(daemon);
        return daemon;
    }

    async function archiveOf(name: string): Promise<string> {
        return packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'data/greeting.txt', bytes: Buffer.from('hello there') },
                { path: 'data/handling.meta', bytes: Buffer.from('<handling/>') },
                { path: 'art.yft', bytes: resourceBytes(), class: 'resource', storage: 'stored' },
            ],
            directories: ['empty'],
        });
    }

    /** An archive holding another, which is the shape this product is for. */
    async function nestedOf(name: string): Promise<string> {
        const inner = await packArchive(path.join(dir, `${name}-inner.rpf`), {
            entries: [{ path: 'data/vehicles.meta', bytes: Buffer.from('<vehicles/>') }],
        });
        return packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'x64/inner.rpf', bytes: fs.readFileSync(inner), storage: 'stored' },
                { path: 'readme.txt', bytes: Buffer.from('hi') },
            ],
        });
    }

    it('holds an edit until the archive is saved, and nothing reaches disk before', async () => {
        const archive = await archiveOf('buffered');
        const before = fs.readFileSync(archive);
        const session = await ArchiveSession.open(start(), archive);

        assert.equal(session.state, 'clean');
        await session.write('data/greeting.txt', Buffer.from('replaced'));
        assert.equal(session.state, 'dirty');
        assert.deepEqual(session.dirtyPaths(), ['data/greeting.txt']);
        assert.deepEqual(fs.readFileSync(archive), before, 'the file changed before the save');

        assert.deepEqual(await session.read('data/greeting.txt'), Buffer.from('replaced'));
        assert.equal(session.lengthOf('data/greeting.txt'), 'replaced'.length);

        const saved = await session.save();
        assert.equal(saved?.committed, 1);
        assert.equal(session.state, 'clean');
        assert.deepEqual(session.dirtyPaths(), []);
        assert.notDeepEqual(fs.readFileSync(archive), before, 'the save did not take');
        assert.deepEqual(await session.read('data/greeting.txt'), Buffer.from('replaced'));
    });

    it('reports nothing to save when nothing is buffered', async () => {
        const archive = await archiveOf('nothing');
        const before = fs.readFileSync(archive);
        const session = await ArchiveSession.open(start(), archive);
        assert.equal(await session.save(), undefined);
        assert.deepEqual(fs.readFileSync(archive), before);
    });

    it('drops every buffered edit on both sides when told to', async () => {
        const archive = await archiveOf('discard');
        const before = fs.readFileSync(archive);
        const session = await ArchiveSession.open(start(), archive);
        await session.write('data/greeting.txt', Buffer.from('replaced'));
        assert.equal(await session.discard(), 1);
        assert.equal(session.state, 'clean');
        assert.equal(await session.save(), undefined);
        assert.deepEqual(fs.readFileSync(archive), before);
    });

    it('decides patch or rebuild for the whole set, not for each edit', async () => {
        // R4.14: one edit that does not fit holds back one that does, because
        // the archive is written once for the set.
        const archive = await archiveOf('set');
        const session = await ArchiveSession.open(start(), archive);

        await session.write('data/greeting.txt', Buffer.from('tiny'));
        assert.equal((await session.preview()).method, 'patch');

        await session.write('data/handling.meta', incompressible(64 * 1024));
        const preview = await session.preview();
        assert.equal(preview.method, 'rebuild');
        assert.deepEqual(
            preview.rejected.map((entry) => entry.path),
            ['data/handling.meta'],
        );
        assert.equal(session.state, 'dirty', 'a dry run must keep the edits');
        assert.deepEqual(session.dirtyPaths().sort(), ['data/greeting.txt', 'data/handling.meta']);

        const saved = await session.save();
        assert.equal(saved?.method, 'rebuild');
        assert.equal(saved?.committed, 2);
        assert.deepEqual(await session.read('data/greeting.txt'), Buffer.from('tiny'));
    });

    it('patches in place when every edit fits where it already sits', async () => {
        const archive = await archiveOf('patch');
        const before = fs.statSync(archive).size;
        const session = await ArchiveSession.open(start(), archive);
        await session.write('data/greeting.txt', Buffer.from('hello world'));
        const saved = await session.save();
        assert.equal(saved?.method, 'patch');
        assert.equal(fs.statSync(archive).size, before, 'a patch in place changes no length');
    });

    it('leaves the edits buffered when a save is cancelled, so it can be asked again', async () => {
        const archive = path.join(dir, 'cancelled.rpf');
        await packArchive(archive, {
            entries: Array.from({ length: 16 }, (_, at) => ({
                path: `bulk/${String(at).padStart(2, '0')}.bin`,
                bytes: incompressible(512 * 1024),
            })),
        });
        const before = fs.readFileSync(archive);
        const session = await ArchiveSession.open(start(), archive);
        await session.write('bulk/00.bin', Buffer.from('replaced'));

        let settled = false;
        const stopping = session.save({
            rebuild: true,
            onProgress: () => {
                if (!settled) {
                    void session.cancelSave().catch(() => undefined);
                }
            },
        });
        const failure = await stopping.then(
            () => undefined,
            (error: unknown) => error,
        );
        settled = true;
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.cancelled);
        assert.equal(advise(failure).kind, 'cancelled');
        assert.deepEqual(fs.readFileSync(archive), before, 'a cancelled rebuild wrote something');

        assert.equal(session.state, 'dirty', 'the edits went with the cancellation');
        assert.deepEqual(session.dirtyPaths(), ['bulk/00.bin']);
        const saved = await session.save();
        assert.equal(saved?.committed, 1, 'the same save could not be asked for again');
    });

    it('refuses to start a second save while one is running', async () => {
        const archive = await archiveOf('busy');
        const session = await ArchiveSession.open(start(), archive);
        await session.write('data/greeting.txt', Buffer.from('replaced'));
        const first = session.save();
        await assert.rejects(() => session.save(), SessionBusy);
        await first;
    });

    it('refuses a second session on one archive, naming the handle that holds it', async () => {
        // DR-009: every offset a session holds is true only of the bytes it
        // parsed, so this is refused rather than detected later.
        const archive = await archiveOf('claimed');
        const daemon = start();
        const first = await ArchiveSession.open(daemon, archive);
        const failure = await ArchiveSession.open(daemon, archive).then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.refused);
        assert.match(failure.reason, new RegExp(`handle ${first.handle}`));
        assert.equal(advise(failure).kind, 'refused');

        await first.close();
        const second = await ArchiveSession.open(daemon, archive);
        assert.ok(second.handle > first.handle, 'closing did not release the claim');
    });

    it('refuses one archive under a second name for the same file', async () => {
        // A hard link is two names for one file, and the corruption DR-009
        // exists to prevent arrives through the second of them.
        const archive = await archiveOf('linked');
        const alias = path.join(dir, 'alias.rpf');
        fs.linkSync(archive, alias);
        const daemon = start();
        await ArchiveSession.open(daemon, archive);
        const failure = await ArchiveSession.open(daemon, alias).then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.refused);
        assert.match(failure.reason, /another name for/);
    });

    it('edits a file inside a nested archive and reads the result back', async () => {
        // The shape this product is for: the payload sits one archive deeper
        // than the file the server loads. `docs/approach.md`.
        const archive = await nestedOf('nested');
        const session = await ArchiveSession.open(start(), archive);

        const inner = session.tree.at('x64/inner.rpf');
        assert.equal(inner?.kind, 'archive', 'the nested archive is not descendable');
        assert.equal(session.tree.at('x64/inner.rpf/data/vehicles.meta')?.kind, 'binary');

        await session.write(
            'x64/inner.rpf/data/vehicles.meta',
            Buffer.from('<vehicles><one/></vehicles>'),
        );
        const saved = await session.save();
        assert.ok(saved, 'the nested edit did not commit');
        assert.deepEqual(
            await session.read('x64/inner.rpf/data/vehicles.meta'),
            Buffer.from('<vehicles><one/></vehicles>'),
        );

        const verified = await session.verify();
        assert.deepEqual(verified.problems, [], 'the rebuilt archive does not verify');
    });

    it('refreshes the tree after a save, so a new length is the one reported', async () => {
        const archive = await archiveOf('refresh');
        const session = await ArchiveSession.open(start(), archive);
        assert.equal(session.tree.at('data/greeting.txt')?.len, 'hello there'.length);
        await session.write('data/greeting.txt', Buffer.from('a much longer greeting than before'));
        await session.save();
        assert.equal(
            session.tree.at('data/greeting.txt')?.len,
            'a much longer greeting than before'.length,
        );
    });

    it('refuses a payload a resource entry cannot hold, while the user can still act', async () => {
        // R6.6, and refused at the write rather than at the save: the caller
        // finds out while it still knows which edit it made.
        const archive = await archiveOf('resource');
        const session = await ArchiveSession.open(start(), archive);
        const failure = await session.write('art.yft', Buffer.from('plain text')).then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.refused);
        assert.match(failure.reason, /RSC7/);
        assert.equal(session.state, 'clean', 'a refused write made the archive dirty');

        await session.write('art.yft', resourceBytes());
        assert.equal(session.state, 'dirty');
    });

    it('refuses to write a directory as though it were a file', async () => {
        const archive = await archiveOf('directory');
        const session = await ArchiveSession.open(start(), archive);
        const failure = await session.write('data', Buffer.from('x')).then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.refused);
    });

    it('loses buffered edits when the session closes, and says how many', async () => {
        const archive = await archiveOf('closing');
        const before = fs.readFileSync(archive);
        const session = await ArchiveSession.open(start(), archive);
        await session.write('data/greeting.txt', Buffer.from('replaced'));
        assert.equal(await session.close(), 1, 'closing must say what it discarded');
        assert.deepEqual(fs.readFileSync(archive), before);
    });

    it('reports its state changes as they happen', async () => {
        const archive = await archiveOf('states');
        const session = await ArchiveSession.open(start(), archive);
        const seen: string[] = [];
        session.onStateChange((state) => seen.push(state));
        await session.write('data/greeting.txt', Buffer.from('replaced'));
        await session.save();
        assert.deepEqual(seen, ['dirty', 'saving', 'clean']);
    });
});
