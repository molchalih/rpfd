/**
 * Adding, removing and renaming an entry, against a live daemon. R4.10, DR-026.
 *
 * The point of every case here is the same one: **`list` is the archive on
 * disk** (DR-028), so the assertion that matters is always the one made
 * *before* the save — the session's own view against what the daemon would
 * still report. DR-030.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { Daemon } from '../src/core/daemon.js';
import { DaemonError, EXIT, Refused } from '../src/core/errors.js';
import { ArchiveSession } from '../src/core/session.js';
import type { Listed } from '../src/core/protocol.js';
import { SKIP, binary, packArchive, resourceBytes, scratch } from './support.js';

describe('changing what an archive holds', { skip: SKIP }, () => {
    const dir = scratch('structure');
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

    async function openArchive(name: string): Promise<ArchiveSession> {
        const archive = await packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'data/greeting.txt', bytes: Buffer.from('hello there') },
                { path: 'data/handling.meta', bytes: Buffer.from('<handling/>') },
                { path: 'readme.txt', bytes: Buffer.from('hi') },
                { path: 'art.yft', bytes: resourceBytes(), class: 'resource', storage: 'stored' },
            ],
            directories: ['empty'],
        });
        return ArchiveSession.open(start(), archive);
    }

    /** One request to the daemon this session holds, around the session. */
    function wire<T>(session: ArchiveSession, method: string, params: unknown): Promise<T> {
        return (
            session as unknown as {
                daemon: { request: (m: string, p: unknown) => Promise<T> };
            }
        ).daemon.request(method, params);
    }

    /** What the daemon's own `list` reports, which is the archive on disk. */
    async function listed(session: ArchiveSession): Promise<string[]> {
        const rows = await wire<Listed[]>(session, 'list', {
            handle: session.handle,
            recursive: true,
        });
        return rows.map((row) => row.path).sort();
    }

    /** The set the **daemon** holds, which the session's own must equal. */
    async function buffered(session: ArchiveSession): Promise<string[]> {
        const answer = await wire<{ paths: string[] }>(session, 'pending', {
            handle: session.handle,
        });
        return answer.paths.sort();
    }

    function shown(session: ArchiveSession): string[] {
        const out: string[] = [];
        const walk = (inside: string): void => {
            for (const child of session.tree.childrenOf(inside)) {
                out.push(child.path);
                walk(child.path);
            }
        };
        walk('');
        return out.sort();
    }

    it('shows a created entry before the commit, while the listing still does not', async () => {
        const session = await openArchive('created');
        await session.write('x64/new.txt', Buffer.from('brand new'), { create: true });

        assert.ok(shown(session).includes('x64/new.txt'), 'the view does not hold the creation');
        assert.ok(shown(session).includes('x64'), 'the parent the creation needs is not there');
        assert.ok(
            !(await listed(session)).includes('x64/new.txt'),
            'DR-028 says a listing is the archive on disk; this one was not',
        );
        assert.equal(session.committed.at('x64/new.txt'), undefined);
        assert.equal(session.state, 'dirty');
        assert.deepEqual(await session.read('x64/new.txt'), Buffer.from('brand new'));
        assert.equal(session.tree.at('x64/new.txt')?.len, 'brand new'.length);

        const saved = await session.save();
        assert.equal(saved?.method, 'rebuild', 'an entry added is always a rebuild');
        assert.ok((await listed(session)).includes('x64/new.txt'), 'the commit did not add it');
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('hides a deleted entry before the commit, while the listing still holds it', async () => {
        const session = await openArchive('deleted');
        await session.remove('readme.txt');

        assert.equal(session.tree.at('readme.txt'), undefined, 'the view still holds it');
        assert.ok(
            (await listed(session)).includes('readme.txt'),
            'a listing before the commit must still hold it',
        );

        await session.save();
        assert.ok(!(await listed(session)).includes('readme.txt'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('shows a renamed entry under its new name before the commit', async () => {
        const session = await openArchive('renamed');
        await session.rename('data', 'info');

        assert.ok(shown(session).includes('info/greeting.txt'));
        assert.ok(!shown(session).includes('data/greeting.txt'));
        assert.ok((await listed(session)).includes('data/greeting.txt'), 'the listing moved');
        assert.deepEqual(await session.read('info/greeting.txt'), Buffer.from('hello there'));

        await session.save();
        assert.ok((await listed(session)).includes('info/greeting.txt'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('takes a directory\'s children only when asked, and refuses otherwise', async () => {
        const session = await openArchive('recursive');
        const refusal = await session.remove('data').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'refused');
        assert.equal(session.state, 'clean');

        await session.remove('data', { recursive: true });
        assert.equal(session.tree.at('data'), undefined);
        assert.equal(session.tree.at('data/greeting.txt'), undefined);
        await session.save();
        assert.deepEqual(await listed(session), ['art.yft', 'empty', 'readme.txt']);
    });

    it('counts a buffered creation when it asks whether a directory is empty', async () => {
        // The one question the daemon cannot answer for the client. Measured
        // against a live daemon, 2026-08-29: `write empty/fresh.txt
        // {create:true}` and then `delete empty {recursive:false}` is
        // **accepted**, pending 2, and the commit puts `empty/fresh.txt` there
        // — because `tree_of` removes an empty directory and then the write
        // implies it again. That is the set doing what the set says; it is not
        // what "delete this folder" meant, and the view is the only place both
        // halves are visible.
        const session = await openArchive('empty-with-buffered');
        await session.write('empty/fresh.txt', Buffer.from('x'), { create: true });
        const refusal = await session.remove('empty').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.match(refusal.message, /not empty/);

        await session.remove('empty', { recursive: true });
        assert.deepEqual(session.dirtyPaths(), ['empty'], 'the creation inside it stayed');
        assert.deepEqual(await buffered(session), ['empty']);
        await session.save();
        assert.ok(!(await listed(session)).includes('empty'));
        assert.ok(!(await listed(session)).includes('empty/fresh.txt'));
    });

    it('deletes an empty directory with nothing said', async () => {
        const session = await openArchive('empty-directory');
        await session.remove('empty');
        await session.save();
        assert.ok(!(await listed(session)).includes('empty'));
    });

    it('makes a directory, and refuses one over something that is there', async () => {
        const session = await openArchive('mkdir');
        await session.makeDirectory('fresh');
        assert.equal(session.tree.at('fresh')?.kind, 'directory');
        const refusal = await session.makeDirectory('data').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'exists');
        await session.save();
        assert.ok((await listed(session)).includes('fresh'));
    });

    it('withdraws a creation when it is deleted again, rather than asking the daemon', async () => {
        // `delete` of a path only a buffered write put there is `Claimed`: the
        // set holds a write there, and one set holds one change per path. So
        // this is the change withdrawn, which is one `forget` — where it used
        // to be the whole set discarded and offered again. DR-030 §3, DR-032.
        const session = await openArchive('withdrawn');
        const before = fs.readFileSync(session.path);
        await session.write('gone.txt', Buffer.from('temporary'), { create: true });
        await session.remove('gone.txt');

        assert.equal(session.state, 'clean');
        assert.deepEqual(session.dirtyPaths(), []);
        assert.equal(session.tree.at('gone.txt'), undefined);
        assert.equal(await session.save(), undefined, 'a withdrawn creation left something to save');
        assert.deepEqual(fs.readFileSync(session.path), before);
    });

    it('keeps a created entry editable before the commit', async () => {
        const session = await openArchive('edit-created');
        await session.write('draft.txt', Buffer.from('one'), { create: true });
        await session.write('draft.txt', Buffer.from('two, longer'), { create: true });
        assert.equal(session.tree.at('draft.txt')?.len, 'two, longer'.length);
        assert.deepEqual(await session.read('draft.txt'), Buffer.from('two, longer'));
        await session.save();
        assert.deepEqual(await session.read('draft.txt'), Buffer.from('two, longer'));
    });

    it('edits an entry inside a directory a buffered rename has moved', async () => {
        // The write is keyed by the path the archive holds the entry at, and
        // the rename is keyed by the directory's — two changes at two paths,
        // which one set holds. `edit::tree_of` renames first and then finds the
        // entry by its index, so the two compose.
        const session = await openArchive('edit-under-rename');
        await session.rename('data', 'info');
        await session.write('info/greeting.txt', Buffer.from('a much longer greeting than before'));
        assert.deepEqual(session.dirtyPaths(), ['data', 'data/greeting.txt']);
        assert.equal(session.tree.at('info/greeting.txt')?.len, 34);
        await session.save();
        assert.deepEqual(
            await session.read('info/greeting.txt'),
            Buffer.from('a much longer greeting than before'),
        );
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('refuses to edit an entry whose own rename is buffered', async () => {
        // A rename and a write are two changes at one path, and
        // `edit::Changes` holds one change per path with no variant that does
        // both — so there is no set that expresses it, and buffering the write
        // would drop the rename without saying so. DR-030.
        const session = await openArchive('edit-renamed');
        await session.rename('readme.txt', 'notes.txt');
        const refusal = await session.write('notes.txt', Buffer.from('longer than before')).then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'refused');
        assert.match(refusal.message, /one change per entry/);
        assert.deepEqual(session.dirtyPaths(), ['readme.txt'], 'the rename was lost');
    });

    it('refuses to rename an entry whose own edit is buffered', async () => {
        // The mirror of the case above, and the same reason: one change per
        // path, no variant that does both. It used to be *accepted* here and
        // the write silently replaced — which is the failure DR-032 §3 fixed on
        // the wire, and this side held the same bug. Neither set may replace
        // where the other refuses, or the two stop being one set.
        const session = await openArchive('rename-edited');
        await session.write('readme.txt', Buffer.from('longer than before'));
        const refusal = await session.rename('readme.txt', 'notes.txt').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'refused');
        assert.match(refusal.message, /one change per path/);
        assert.deepEqual(session.dirtyPaths(), ['readme.txt'], 'the write was lost');
        assert.deepEqual(await buffered(session), ['readme.txt']);
        assert.deepEqual(await session.read('readme.txt'), Buffer.from('longer than before'));
    });

    it('takes back the change a gesture supersedes, rather than stacking a second at one path', async () => {
        // Deleting an entry that has a buffered edit, and writing one back over
        // a buffered removal, are each **one** change in the set that commits.
        // The daemon refuses the second offered at a key its set holds
        // (`Error::Claimed`), so each of these is a `forget` and then the
        // change that is meant — one request each, where withdrawing anything
        // used to cost a discard and a replay. DR-032 §4.
        const session = await openArchive('superseded');
        await session.write('readme.txt', Buffer.from('edited first'));
        await session.remove('readme.txt');
        assert.deepEqual(session.dirtyPaths(), ['readme.txt']);
        assert.deepEqual(await buffered(session), ['readme.txt']);
        assert.equal(session.tree.at('readme.txt'), undefined);

        await session.write('readme.txt', Buffer.from('and put back'), { create: true });
        assert.deepEqual(session.dirtyPaths(), ['readme.txt']);
        assert.deepEqual(await buffered(session), ['readme.txt']);
        assert.deepEqual(await session.read('readme.txt'), Buffer.from('and put back'));

        const saved = await session.save();
        assert.equal(saved?.committed, 1, 'one path, one change');
        assert.deepEqual(await session.read('readme.txt'), Buffer.from('and put back'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('renames an entry twice into the one rename the daemon can resolve', async () => {
        // Two renames of one entry are one change, keyed by the path the
        // archive holds it at — and the daemon **refuses** the composed rename
        // offered at a key its set already holds rather than replacing what is
        // there, so the first has to be taken back before the second goes.
        // DR-032 §3. Both halves are asserted: that the client withdraws, and
        // that the wire is what makes it have to.
        const session = await openArchive('renamed-twice');
        await session.rename('readme.txt', 'middle.txt');
        await session.rename('middle.txt', 'final.txt');
        assert.deepEqual(session.dirtyPaths(), ['readme.txt']);
        assert.deepEqual(await buffered(session), ['readme.txt'], 'the daemon holds another set');
        assert.ok(shown(session).includes('final.txt'));

        const claimed = await wire(session, 'rename', {
            handle: session.handle,
            from: 'readme.txt',
            to: 'elsewhere.txt',
        }).then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(claimed instanceof DaemonError, String(claimed));
        assert.equal(claimed.code, EXIT.refused, 'a second change at one path must be refused');
        assert.equal(claimed.failure, 'Claimed');
        assert.deepEqual(await buffered(session), ['readme.txt'], 'a refusal changed the set');

        await session.save();
        assert.ok((await listed(session)).includes('final.txt'));
        assert.ok(!(await listed(session)).includes('middle.txt'));
    });

    it('withdraws a rename that puts the entry back where it was', async () => {
        const session = await openArchive('renamed-back');
        const before = fs.readFileSync(session.path);
        await session.rename('readme.txt', 'elsewhere.txt');
        await session.rename('elsewhere.txt', 'readme.txt');
        assert.equal(session.state, 'clean');
        assert.equal(await session.save(), undefined);
        assert.deepEqual(fs.readFileSync(session.path), before);
    });

    it('renames a created entry by moving the change, not by renaming what is not there', async () => {
        const session = await openArchive('rename-created');
        await session.makeDirectory('fresh');
        await session.write('fresh/one.txt', Buffer.from('x'), { create: true });
        await session.rename('fresh', 'later');
        assert.deepEqual(session.dirtyPaths(), ['later', 'later/one.txt']);
        assert.ok(shown(session).includes('later/one.txt'));
        assert.ok(!shown(session).includes('fresh'));
        await session.save();
        assert.ok((await listed(session)).includes('later/one.txt'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('renames onto a path a buffered removal is about to free', async () => {
        // DR-026 says a caller that means to replace the target removes it in
        // the same set, and removals are applied before renames for exactly
        // that reason. The wire could not carry that set — a rename was
        // resolved against the archive on disk, where the target is still
        // there — and DR-032 made `allows` judge a change against the changes
        // buffered beside it, so now it can.
        const session = await openArchive('rename-over-removed');
        await session.remove('readme.txt');
        await session.rename('data/greeting.txt', 'readme.txt');
        assert.deepEqual(session.dirtyPaths(), ['data/greeting.txt', 'readme.txt']);
        assert.deepEqual(await buffered(session), ['data/greeting.txt', 'readme.txt']);
        assert.equal(session.tree.at('data/greeting.txt'), undefined);
        assert.equal(session.tree.at('readme.txt')?.len, 'hello there'.length);

        const saved = await session.save();
        assert.equal(saved?.method, 'rebuild');
        assert.deepEqual(await listed(session), ['art.yft', 'data', 'data/handling.meta', 'empty', 'readme.txt']);
        assert.deepEqual(await session.read('readme.txt'), Buffer.from('hello there'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('replaces an entry a rename is asked to overwrite, by removing it in the same set', async () => {
        // Not a delete and a create: that would change the entry's storage
        // class and its kind behind the user's back, which is why DR-026
        // refused an `overwrite` on the rename itself. What is assembled here
        // is the set DR-026 names — the target removed, then the rename over
        // it — which DR-032 made offerable one change at a time. DR-030 §6.
        const session = await openArchive('rename-overwrite');
        const refusal = await session.rename('data/greeting.txt', 'readme.txt').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'exists', 'a rename with no overwrite must still refuse');

        await session.rename('data/greeting.txt', 'readme.txt', { overwrite: true });
        assert.deepEqual(session.dirtyPaths(), ['data/greeting.txt', 'readme.txt']);
        assert.equal(session.tree.at('readme.txt')?.len, 'hello there'.length);

        // A directory holding entries is not what "replace this" is asked
        // about, and taking it recursively is a deletion nobody asked for.
        const directory = await session.rename('art.yft', 'data', { overwrite: true }).then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(directory instanceof Refused, String(directory));
        assert.match(directory.message, /not empty/);

        await session.save();
        assert.deepEqual(await session.read('readme.txt'), Buffer.from('hello there'));
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('refuses a rename inside a directory whose own rename is buffered', async () => {
        // `edit::tree_of` applies renames in path order, so the directory's
        // runs first and the inner one is left addressing a path the tree no
        // longer holds — a commit that answers exit 3 for a set both halves of
        // which were accepted when they were offered.
        const session = await openArchive('overlapping-renames');
        await session.rename('data', 'info');
        const refusal = await session.rename('info/greeting.txt', 'info/hello.txt').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'refused');
        assert.match(refusal.message, /already being renamed/);
    });

    it('refuses a rename onto an occupied path, with no way through', async () => {
        const session = await openArchive('rename-occupied');
        const refusal = await session.rename('readme.txt', 'data/greeting.txt').then(
            () => undefined,
            (failure: unknown) => failure,
        );
        assert.ok(refusal instanceof Refused, String(refusal));
        assert.equal(refusal.kind, 'exists');
    });

    it('refuses to create a path the archive does not hold without being asked to', async () => {
        const session = await openArchive('no-create');
        const failure = await session.write('nowhere.txt', Buffer.from('x')).then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, String(failure));
        assert.equal(failure.code, EXIT.notFound);
        assert.equal(session.state, 'clean');
    });

    it('puts everything back where it was when the changes are discarded', async () => {
        const session = await openArchive('discarded');
        const before = shown(session);
        await session.write('added.txt', Buffer.from('x'), { create: true });
        await session.remove('readme.txt');
        await session.rename('data', 'info');
        await session.makeDirectory('fresh');
        assert.equal(session.dirtyPaths().length, 4);

        assert.equal(await session.discard(), 4);
        assert.equal(session.state, 'clean');
        assert.deepEqual(shown(session), before);
        assert.equal(await session.save(), undefined);
    });

    it('commits a whole set in one rebuild, and reports it as structural first', async () => {
        const session = await openArchive('set');
        await session.write('added.txt', Buffer.from('added'), { create: true });
        await session.remove('readme.txt');
        await session.rename('data/handling.meta', 'data/handling.xml');
        await session.makeDirectory('fresh');

        const preview = await session.preview();
        assert.equal(preview.method, 'rebuild');
        assert.deepEqual(
            preview.structural.map((one) => `${one.path}: ${one.structural}`).sort(),
            [
                'added.txt: adds an entry',
                'data/handling.meta: renames an entry',
                'fresh: adds a directory',
                'readme.txt: removes an entry',
            ],
        );
        assert.equal(session.state, 'dirty', 'a dry run must keep the changes');

        const saved = await session.save();
        assert.equal(saved?.method, 'rebuild');
        assert.equal(saved?.committed, 4);
        assert.deepEqual(await listed(session), [
            'added.txt',
            'art.yft',
            'data',
            'data/greeting.txt',
            'data/handling.xml',
            'empty',
            'fresh',
        ]);
        assert.deepEqual((await session.verify()).problems, []);
    });

    it('changes what a nested archive holds, and verifies afterwards', async () => {
        const inner = await packArchive(path.join(dir, 'nested-inner.rpf'), {
            entries: [{ path: 'data/vehicles.meta', bytes: Buffer.from('<vehicles/>') }],
        });
        const archive = await packArchive(path.join(dir, 'nested.rpf'), {
            entries: [
                { path: 'x64/inner.rpf', bytes: fs.readFileSync(inner), storage: 'stored' },
                { path: 'readme.txt', bytes: Buffer.from('hi') },
            ],
        });
        const session = await ArchiveSession.open(start(), archive);

        await session.write('x64/inner.rpf/data/extra.meta', Buffer.from('<extra/>'), {
            create: true,
        });
        assert.equal(session.tree.at('x64/inner.rpf/data/extra.meta')?.kind, 'binary');
        assert.ok(
            !(await listed(session)).includes('x64/inner.rpf/data/extra.meta'),
            'the listing showed a buffered creation',
        );

        await session.save();
        assert.ok((await listed(session)).includes('x64/inner.rpf/data/extra.meta'));
        assert.deepEqual(
            await session.read('x64/inner.rpf/data/extra.meta'),
            Buffer.from('<extra/>'),
        );
        assert.deepEqual((await session.verify()).problems, []);
    });
});

/**
 * The wire facts the model above is built on, asserted against the daemon
 * directly rather than through the session — because they are the reason the
 * session is shaped as it is, and a change to any of them should fail here
 * first. DR-030's argument is exactly this list.
 */
describe('what the daemon answers about a buffered change', { skip: SKIP }, () => {
    const dir = scratch('wire');
    const running: Daemon[] = [];

    after(async () => {
        await Promise.all(running.map((daemon) => daemon.dispose()));
        fs.rmSync(dir, { recursive: true, force: true });
    });

    async function open(name: string): Promise<{ daemon: Daemon; handle: number }> {
        const archive = await packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'data/greeting.txt', bytes: Buffer.from('hello there') },
                { path: 'readme.txt', bytes: Buffer.from('hi') },
            ],
        });
        const daemon = Daemon.start({ binary: binary() });
        running.push(daemon);
        const opened = await daemon.request<{ handle: number }>('open', { path: archive });
        return { daemon, handle: opened.handle };
    }

    const encode = (text: string): string => Buffer.from(text).toString('base64');

    async function refusal(call: Promise<unknown>): Promise<DaemonError> {
        const failure = await call.then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(failure instanceof DaemonError, `expected a refusal, got ${String(failure)}`);
        return failure;
    }

    it('leaves a buffered creation out of the listing, and reads it back all the same', async () => {
        const { daemon, handle } = await open('listing');
        await daemon.request('write', {
            handle,
            path: 'new.txt',
            bytes: encode('brand new'),
            create: true,
        });
        const rows = await daemon.request<{ path: string }[]>('list', { handle, recursive: true });
        assert.ok(!rows.some((row) => row.path === 'new.txt'), 'a listing showed a buffered change');
        const read = await daemon.request<{ pending: boolean }>('read', { handle, path: 'new.txt' });
        assert.equal(read.pending, true, 'read must prefer what was buffered');
    });

    it('will not delete a path only a buffered creation put there', async () => {
        // It was exit 3 — a change was resolved against the archive on disk,
        // where nothing holds the path — and is now exit 6 `Claimed`: the set
        // holds a write there, and a removal at that key would replace it.
        // Neither could ever have been committed; what changed is that the
        // refusal now names the change in the way. DR-032 §3.
        const { daemon, handle } = await open('delete-created');
        await daemon.request('write', { handle, path: 'new.txt', bytes: encode('x'), create: true });
        const failure = await refusal(daemon.request('delete', { handle, path: 'new.txt' }));
        assert.equal(failure.code, EXIT.refused);
        assert.equal(failure.failure, 'Claimed', 'every error carries its own name beside its code');
        assert.match(failure.reason, /a write/, 'a refusal must name what is in the way');
        const still = await daemon.request<{ paths: string[] }>('pending', { handle });
        assert.deepEqual(still.paths, ['new.txt'], 'a refusal must leave the set alone');
    });

    it('will not write again to a buffered creation without being told to create', async () => {
        const { daemon, handle } = await open('rewrite-created');
        await daemon.request('write', { handle, path: 'new.txt', bytes: encode('x'), create: true });
        const failure = await refusal(
            daemon.request('write', { handle, path: 'new.txt', bytes: encode('y'), create: false }),
        );
        assert.equal(failure.code, EXIT.notFound);
    });

    it('renames onto a path a buffered removal is about to free', async () => {
        // DR-026 says removing the target in the same set is how a caller means
        // to replace it, and removals are applied before renames for that
        // reason. A change is now judged against the buffered set as well as
        // the archive, so the set that says it can be assembled one change at a
        // time. DR-032 §1.
        const { daemon, handle } = await open('rename-over-removed');
        await daemon.request('delete', { handle, path: 'readme.txt' });
        const renamed = await daemon.request<{ pending: number }>('rename', {
            handle,
            from: 'data/greeting.txt',
            to: 'readme.txt',
        });
        assert.equal(renamed.pending, 2, 'the replacing rename is one set of two changes');

        // And the archive is still what a change is judged against: the same
        // rename without the removal beside it is refused, by its own name.
        const { daemon: other, handle: occupied } = await open('rename-over-occupied');
        const failure = await refusal(
            other.request('rename', { handle: occupied, from: 'data/greeting.txt', to: 'readme.txt' }),
        );
        assert.equal(failure.code, EXIT.refused);
        assert.equal(failure.failure, 'AlreadyExists');
        assert.match(failure.reason, /already in the archive/);
    });

    it('will not rename a path a buffered rename put there', async () => {
        const { daemon, handle } = await open('rename-twice');
        await daemon.request('rename', { handle, from: 'readme.txt', to: 'moved.txt' });
        const failure = await refusal(
            daemon.request('rename', { handle, from: 'moved.txt', to: 'again.txt' }),
        );
        assert.equal(failure.code, EXIT.notFound);
    });

    it('takes one buffered change back, and says what is left', async () => {
        // `discard` is all of them, which is why withdrawing one used to cost a
        // discard and a replay of the rest — and why the client had to retain
        // every buffered payload to be able to send it again. DR-030 §3 asked
        // for this method; DR-032 §4 is where it was decided.
        const { daemon, handle } = await open('forget');
        await daemon.request('write', { handle, path: 'new.txt', bytes: encode('x'), create: true });
        await daemon.request('delete', { handle, path: 'readme.txt' });

        const forgotten = await daemon.request<{
            path: string;
            forgotten: boolean;
            pending: number;
            paths: string[];
        }>('forget', { handle, path: 'new.txt' });
        assert.deepEqual(forgotten, {
            path: 'new.txt',
            forgotten: true,
            pending: 1,
            paths: ['readme.txt'],
        });

        // A path nothing is buffered at is answered rather than refused: a
        // client withdrawing a gesture it may never have sent should not have
        // to track that.
        const nothing = await daemon.request<{ forgotten: boolean; paths: string[] }>('forget', {
            handle,
            path: 'new.txt',
        });
        assert.equal(nothing.forgotten, false);
        assert.deepEqual(nothing.paths, ['readme.txt']);

        // And the withdrawal reaches the archive: what is left is what commits.
        const committed = await daemon.request<{ committed: number }>('commit', { handle });
        assert.equal(committed.committed, 1);
        const rows = await daemon.request<{ path: string }[]>('list', { handle, recursive: true });
        assert.ok(!rows.some((row) => row.path === 'new.txt'), 'a forgotten change was committed');
        assert.ok(!rows.some((row) => row.path === 'readme.txt'), 'the change left was not');
    });
});
