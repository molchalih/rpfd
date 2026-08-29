/**
 * The buffered structure a listing does not show. DR-028, DR-026, DR-030.
 *
 * No daemon here: this is the arithmetic of the change set, and what it does to
 * a listing. That the arithmetic agrees with what the daemon commits is what
 * `session.test.ts` asserts, against a live one.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { Pending } from '../src/core/pending.js';
import type { Listed } from '../src/core/protocol.js';
import { Tree } from '../src/core/tree.js';

const disk: Listed[] = [
    { path: 'data', kind: 'directory', len: 2 },
    { path: 'data/greeting.txt', kind: 'binary', len: 11 },
    { path: 'data/handling.meta', kind: 'binary', len: 11 },
    { path: 'readme.txt', kind: 'binary', len: 2 },
];

const bytes = (text: string): Uint8Array => Buffer.from(text);

function pathsOf(pending: Pending): string[] {
    return pending
        .rowsOver(disk)
        .map((row) => row.path)
        .sort();
}

describe('a buffered change set', () => {
    it('shows a created entry that the listing does not', () => {
        const pending = new Pending();
        assert.equal(pending.record('new.txt', { kind: 'write', contents: bytes('hi'), create: true }), 'one');
        assert.ok(pathsOf(pending).includes('new.txt'), 'the creation is not in the view');
        assert.ok(
            !disk.some((row) => row.path === 'new.txt'),
            'the listing this is layered over must not hold it',
        );
        assert.equal(Tree.of(pending.rowsOver(disk)).at('new.txt')?.len, 2);
    });

    it('hides a deleted entry that the listing still holds', () => {
        const pending = new Pending();
        assert.equal(pending.record('readme.txt', { kind: 'remove', recursive: false }), 'one');
        assert.ok(!pathsOf(pending).includes('readme.txt'));
        assert.equal(Tree.of(pending.rowsOver(disk)).at('readme.txt'), undefined);
    });

    it('takes a directory\'s children with it when the removal is recursive', () => {
        const pending = new Pending();
        pending.record('data', { kind: 'remove', recursive: true });
        assert.deepEqual(pathsOf(pending), ['readme.txt']);
    });

    it('shows a renamed entry under its new name, and nothing under the old', () => {
        const pending = new Pending();
        assert.equal(pending.record('data', { kind: 'rename', to: 'info' }), 'one');
        assert.deepEqual(pathsOf(pending), [
            'info',
            'info/greeting.txt',
            'info/handling.meta',
            'readme.txt',
        ]);
    });

    it('addresses a renamed entry by the path the archive still holds it at', () => {
        const pending = new Pending();
        pending.record('data', { kind: 'rename', to: 'info' });
        assert.equal(pending.address('info/greeting.txt'), 'data/greeting.txt');
        assert.equal(pending.address('readme.txt'), 'readme.txt');
    });

    it('withdraws a creation when the same path is deleted, rather than stacking', () => {
        // The daemon resolves every change against the archive on disk, so
        // `delete` of a path only a buffered write put there is exit 3. The set
        // has to lose the change instead, which its buffer has no method for —
        // hence `resync`. DR-030.
        const pending = new Pending();
        pending.record('new.txt', { kind: 'write', contents: bytes('hi'), create: true });
        assert.equal(pending.record('new.txt', { kind: 'remove', recursive: false }), 'resync');
        assert.equal(pending.size, 0);
        assert.deepEqual(pathsOf(pending), disk.map((row) => row.path).sort());
    });

    it('withdraws a made directory the same way, with whatever was put inside it', () => {
        const pending = new Pending();
        pending.record('fresh', { kind: 'mkdir' });
        pending.record('fresh/x.txt', { kind: 'write', contents: bytes('x'), create: true });
        assert.equal(pending.record('fresh', { kind: 'remove', recursive: true }), 'resync');
        assert.equal(pending.size, 0);
    });

    it('drops the buffered edits a removed directory takes with it', () => {
        const pending = new Pending();
        pending.record('data/greeting.txt', { kind: 'write', contents: bytes('x'), create: false });
        assert.equal(pending.record('data', { kind: 'remove', recursive: true }), 'resync');
        assert.deepEqual(pending.paths(), ['data']);
    });

    it('composes two renames of one entry into the one the daemon can resolve', () => {
        // Every change is resolved against the archive on disk, so a second
        // rename addressed from the first one's destination is exit 3. One
        // change from the path the archive holds is what is left.
        const pending = new Pending();
        pending.record('readme.txt', { kind: 'rename', to: 'moved.txt' });
        const held = pending.address('moved.txt');
        assert.equal(held, 'readme.txt');
        assert.equal(pending.record(held, { kind: 'rename', to: 'again.txt' }), 'one');
        assert.deepEqual(pending.paths(), ['readme.txt']);
        assert.deepEqual(pending.at('readme.txt'), { kind: 'rename', to: 'again.txt' });
        assert.ok(pathsOf(pending).includes('again.txt'));
    });

    it('withdraws a rename that puts an entry back where it came from', () => {
        const pending = new Pending();
        pending.record('readme.txt', { kind: 'rename', to: 'moved.txt' });
        assert.equal(
            pending.record(pending.address('moved.txt'), { kind: 'rename', to: 'readme.txt' }),
            'resync',
        );
        assert.equal(pending.size, 0);
    });

    it('moves a buffered creation rather than renaming what is not there', () => {
        const pending = new Pending();
        pending.record('fresh', { kind: 'mkdir' });
        pending.record('fresh/x.txt', { kind: 'write', contents: bytes('x'), create: true });
        assert.equal(pending.record('fresh', { kind: 'rename', to: 'later' }), 'resync');
        assert.deepEqual(pending.paths(), ['later', 'later/x.txt']);
        assert.ok(pathsOf(pending).includes('later/x.txt'));
    });

    it('keeps a creation inside a renamed directory addressed by its new path', () => {
        const pending = new Pending();
        pending.record('data/new.txt', { kind: 'write', contents: bytes('x'), create: true });
        assert.equal(pending.record('data', { kind: 'rename', to: 'info' }), 'resync');
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
        pending.record('data', { kind: 'rename', to: 'info' });
        assert.equal(pending.blocksRename('data'), undefined);
        assert.match(String(pending.blocksRename('data/greeting.txt')), /data is already being renamed/);

        const other = new Pending();
        other.record('data/greeting.txt', { kind: 'rename', to: 'data/hello.txt' });
        assert.match(String(other.blocksRename('data')), /already being renamed/);
    });

    it('applies removals, then renames, then writes, then directories', () => {
        // DR-026's order, which is what lets one set rename over a path it also
        // removes. Anything else here and the view stops being the archive the
        // commit produces.
        const pending = new Pending();
        pending.record('readme.txt', { kind: 'remove', recursive: false });
        pending.record('data/greeting.txt', { kind: 'rename', to: 'readme.txt' });
        assert.deepEqual(pathsOf(pending), ['data', 'data/handling.meta', 'readme.txt']);
        assert.deepEqual(
            pending.ordered().map(([path, change]) => `${change.kind} ${path}`),
            ['remove readme.txt', 'rename data/greeting.txt'],
        );
    });

    it('reports a buffered write against the path it is keyed by, not the one it shows at', () => {
        const pending = new Pending();
        pending.record('data', { kind: 'rename', to: 'info' });
        pending.record('data/greeting.txt', { kind: 'write', contents: bytes('much longer'), create: false });
        const tree = Tree.of(pending.rowsOver(disk));
        assert.equal(tree.at('info/greeting.txt')?.len, 'much longer'.length);
        assert.equal(tree.at('data/greeting.txt'), undefined);
    });
});
