/**
 * The buffered structure a listing does not show. DR-028, DR-026, DR-030.
 *
 * No daemon here: this is the arithmetic of the change set, and what it does to
 * a listing. That the arithmetic agrees with what the daemon commits is what
 * `session.test.ts` asserts, against a live one.
 *
 * A plan is asserted as well as the set it leaves, because the plan is what the
 * daemon is told — a `forget` for every change a gesture withdraws or re-keys,
 * and an offer for every change it makes. DR-032 §4.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { Refused } from '../src/core/errors.js';
import { type Change, Pending, type Plan } from '../src/core/pending.js';
import type { Listed } from '../src/core/protocol.js';
import { Tree } from '../src/core/tree.js';

const disk: Listed[] = [
    { path: 'data', kind: 'directory', len: 2 },
    { path: 'data/greeting.txt', kind: 'binary', len: 11 },
    { path: 'data/handling.meta', kind: 'binary', len: 11 },
    { path: 'readme.txt', kind: 'binary', len: 2 },
];

const bytes = (text: string): Uint8Array => Buffer.from(text);

/** Plans one change, records it, and answers what the daemon would be told. */
function record(pending: Pending, held: string, change: Change, visible = held): Plan {
    const plan = pending.plan(held, visible, change);
    pending.apply(plan);
    return plan;
}

/** What a plan asks the daemon for, as one readable list. */
function asked(plan: Plan): string[] {
    return [
        ...plan.forget.map((path) => `forget ${path}`),
        ...plan.offer.map(([path, change]) => `${change.kind} ${path}`),
    ];
}

function pathsOf(pending: Pending): string[] {
    return pending
        .rowsOver(disk)
        .map((row) => row.path)
        .sort();
}

describe('a buffered change set', () => {
    it('shows a created entry that the listing does not', () => {
        const pending = new Pending();
        const plan = record(pending, 'new.txt', { kind: 'write', contents: bytes('hi'), create: true });
        assert.deepEqual(asked(plan), ['write new.txt']);
        assert.ok(pathsOf(pending).includes('new.txt'), 'the creation is not in the view');
        assert.ok(
            !disk.some((row) => row.path === 'new.txt'),
            'the listing this is layered over must not hold it',
        );
        assert.equal(Tree.of(pending.rowsOver(disk)).at('new.txt')?.len, 2);
    });

    it('hides a deleted entry that the listing still holds', () => {
        const pending = new Pending();
        const plan = record(pending, 'readme.txt', { kind: 'remove', recursive: false });
        assert.deepEqual(asked(plan), ['remove readme.txt']);
        assert.ok(!pathsOf(pending).includes('readme.txt'));
        assert.equal(Tree.of(pending.rowsOver(disk)).at('readme.txt'), undefined);
    });

    it('takes a directory\'s children with it when the removal is recursive', () => {
        const pending = new Pending();
        record(pending, 'data', { kind: 'remove', recursive: true });
        assert.deepEqual(pathsOf(pending), ['readme.txt']);
    });

    it('shows a renamed entry under its new name, and nothing under the old', () => {
        const pending = new Pending();
        const plan = record(pending, 'data', { kind: 'rename', to: 'info' });
        assert.deepEqual(asked(plan), ['rename data']);
        assert.deepEqual(pathsOf(pending), [
            'info',
            'info/greeting.txt',
            'info/handling.meta',
            'readme.txt',
        ]);
    });

    it('addresses a renamed entry by the path the archive still holds it at', () => {
        const pending = new Pending();
        record(pending, 'data', { kind: 'rename', to: 'info' });
        assert.equal(pending.address('info/greeting.txt'), 'data/greeting.txt');
        assert.equal(pending.address('readme.txt'), 'readme.txt');
    });

    it('withdraws a creation when the same path is deleted, rather than stacking', () => {
        // One `forget` and nothing offered: the set that should hold neither
        // change is reached by taking one back. Stacking is not open to it —
        // the daemon refuses a removal at a path its set holds a write at
        // (`Error::Claimed`), which is what {@link Pending.admits} mirrors.
        const pending = new Pending();
        record(pending, 'new.txt', { kind: 'write', contents: bytes('hi'), create: true });
        const plan = record(pending, 'new.txt', { kind: 'remove', recursive: false });
        assert.deepEqual(asked(plan), ['forget new.txt']);
        assert.equal(pending.size, 0);
        assert.deepEqual(pathsOf(pending), disk.map((row) => row.path).sort());
    });

    it('withdraws a made directory the same way, with whatever was put inside it', () => {
        const pending = new Pending();
        record(pending, 'fresh', { kind: 'mkdir' });
        record(pending, 'fresh/x.txt', { kind: 'write', contents: bytes('x'), create: true });
        const plan = record(pending, 'fresh', { kind: 'remove', recursive: true });
        assert.deepEqual(asked(plan), ['forget fresh/x.txt', 'forget fresh']);
        assert.equal(pending.size, 0);
    });

    it('drops the buffered edits a removed directory takes with it', () => {
        const pending = new Pending();
        record(pending, 'data/greeting.txt', { kind: 'write', contents: bytes('x'), create: false });
        const plan = record(pending, 'data', { kind: 'remove', recursive: true });
        assert.deepEqual(asked(plan), ['forget data/greeting.txt', 'remove data']);
        assert.deepEqual(pending.paths(), ['data']);
    });

    it('composes two renames of one entry into the one the daemon can resolve', () => {
        // Every change is keyed by the path the archive holds the entry at, so
        // two renames of one entry are one change — and the daemon refuses the
        // second offered at that key (`Error::Claimed`) rather than replacing
        // the first, so the first is taken back before the composed one goes.
        const pending = new Pending();
        record(pending, 'readme.txt', { kind: 'rename', to: 'moved.txt' });
        const held = pending.address('moved.txt');
        assert.equal(held, 'readme.txt');
        const plan = record(
            pending,
            held,
            { kind: 'rename', to: 'again.txt' },
            'moved.txt',
        );
        assert.deepEqual(asked(plan), ['forget readme.txt', 'rename readme.txt']);
        assert.deepEqual(pending.paths(), ['readme.txt']);
        assert.deepEqual(pending.at('readme.txt'), { kind: 'rename', to: 'again.txt' });
        assert.ok(pathsOf(pending).includes('again.txt'));
    });

    it('withdraws a rename that puts an entry back where it came from', () => {
        const pending = new Pending();
        record(pending, 'readme.txt', { kind: 'rename', to: 'moved.txt' });
        const plan = record(
            pending,
            pending.address('moved.txt'),
            { kind: 'rename', to: 'readme.txt' },
            'moved.txt',
        );
        assert.deepEqual(asked(plan), ['forget readme.txt']);
        assert.equal(pending.size, 0);
    });

    it('moves a buffered creation rather than renaming what is not there', () => {
        const pending = new Pending();
        record(pending, 'fresh', { kind: 'mkdir' });
        record(pending, 'fresh/x.txt', { kind: 'write', contents: bytes('x'), create: true });
        const plan = record(pending, 'fresh', { kind: 'rename', to: 'later' });
        assert.deepEqual(asked(plan), [
            'forget fresh',
            'forget fresh/x.txt',
            'write later/x.txt',
            'mkdir later',
        ]);
        assert.deepEqual(pending.paths(), ['later', 'later/x.txt']);
        assert.ok(pathsOf(pending).includes('later/x.txt'));
    });

    it('keeps a creation inside a renamed directory addressed by its new path', () => {
        const pending = new Pending();
        record(pending, 'data/new.txt', { kind: 'write', contents: bytes('x'), create: true });
        const plan = record(pending, 'data', { kind: 'rename', to: 'info' });
        assert.deepEqual(asked(plan), ['forget data/new.txt', 'rename data', 'write info/new.txt']);
        assert.deepEqual(pending.paths().sort(), ['data', 'info/new.txt']);
        assert.equal(pending.address('info/new.txt'), 'info/new.txt');
        assert.ok(pathsOf(pending).includes('info/new.txt'));
        assert.ok(pathsOf(pending).includes('info/greeting.txt'));
    });

    it('refuses a second rename that overlaps one already buffered', () => {
        // `edit::tree_of` applies renames in path order, so a directory's runs
        // first and leaves the inner one addressing a path the tree no longer
        // holds: the commit answers exit 3 for a set both halves of which were
        // accepted when they were offered.
        const pending = new Pending();
        record(pending, 'data', { kind: 'rename', to: 'info' });
        assert.equal(pending.blocksRename('data'), undefined);
        assert.match(String(pending.blocksRename('data/greeting.txt')), /data is already being renamed/);

        const other = new Pending();
        record(other, 'data/greeting.txt', { kind: 'rename', to: 'data/hello.txt' });
        assert.match(String(other.blocksRename('data')), /already being renamed/);
    });

    it('refuses a second change of another kind at one path, as the daemon does', () => {
        // `Changes::admits`: a set holds one change per path, two writes
        // replace because saving one file twice is what an editor does, and
        // anything else is `Error::Claimed`. A model that replaced where the
        // daemon refuses would be a model of a set the daemon does not hold.
        // DR-032 §3.
        const pending = new Pending();
        record(pending, 'readme.txt', { kind: 'rename', to: 'moved.txt' });
        assert.match(
            String(pending.admits('readme.txt', { kind: 'write', contents: bytes('x'), create: false })),
            /already has a rename/,
        );
        assert.equal(
            pending.admits('readme.txt', { kind: 'rename', to: 'moved.txt' }),
            undefined,
            'the same change offered again is not a second change',
        );
        assert.throws(
            () => pending.plan('readme.txt', 'moved.txt', { kind: 'write', contents: bytes('x'), create: false }),
            (failure: unknown) => failure instanceof Refused,
        );

        const writes = new Pending();
        record(writes, 'readme.txt', { kind: 'write', contents: bytes('one'), create: false });
        assert.equal(
            writes.admits('readme.txt', { kind: 'write', contents: bytes('two'), create: false }),
            undefined,
            'two writes at one path are a re-save, and replace',
        );
    });

    it('applies removals, then renames, then writes, then directories', () => {
        // DR-026's order, which is what lets one set rename over a path it also
        // removes. Anything else here and the view stops being the archive the
        // commit produces — and a gesture that is two changes offers them out
        // of the order the commit will apply them in.
        const pending = new Pending();
        const replacing = Pending.merged([
            pending.plan('readme.txt', 'readme.txt', { kind: 'rename', to: 'kept.txt' }),
            pending.plan('data/new.txt', 'data/new.txt', {
                kind: 'write',
                contents: bytes('x'),
                create: true,
            }),
            pending.plan('data/greeting.txt', 'data/greeting.txt', {
                kind: 'remove',
                recursive: false,
            }),
            pending.plan('fresh', 'fresh', { kind: 'mkdir' }),
        ]);
        assert.deepEqual(asked(replacing), [
            'remove data/greeting.txt',
            'rename readme.txt',
            'write data/new.txt',
            'mkdir fresh',
        ]);

        record(pending, 'readme.txt', { kind: 'remove', recursive: false });
        record(pending, 'data/greeting.txt', { kind: 'rename', to: 'readme.txt' });
        assert.deepEqual(pathsOf(pending), ['data', 'data/handling.meta', 'readme.txt']);
    });

    it('reports a buffered write against the path it is keyed by, not the one it shows at', () => {
        const pending = new Pending();
        record(pending, 'data', { kind: 'rename', to: 'info' });
        record(pending, 'data/greeting.txt', {
            kind: 'write',
            contents: bytes('much longer'),
            create: false,
        });
        const tree = Tree.of(pending.rowsOver(disk));
        assert.equal(tree.at('info/greeting.txt')?.len, 'much longer'.length);
        assert.equal(tree.at('data/greeting.txt'), undefined);
    });
});
