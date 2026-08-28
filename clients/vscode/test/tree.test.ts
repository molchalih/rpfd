import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Listed } from '../src/core/protocol.js';
import { Tree, isDirectory } from '../src/core/tree.js';

/** The rows a recursive listing of a nested archive reports. */
const rows: Listed[] = [
    { kind: 'directory', len: 0, path: 'empty' },
    { kind: 'binary', len: 2, path: 'readme.txt' },
    { kind: 'directory', len: 1, path: 'x64' },
    { kind: 'binary', len: 1024, path: 'x64/inner.rpf' },
    { kind: 'directory', len: 1, path: 'x64/inner.rpf/data' },
    { kind: 'binary', len: 11, path: 'x64/inner.rpf/data/vehicles.meta' },
    { kind: 'resource', len: 512, path: 'art.yft' },
];

describe('an archive tree', () => {
    it('reads a nested archive as a directory because something was listed inside it', () => {
        // Not by its name and not by its first four bytes: the daemon listed
        // entries beneath it, and that is the only reading of "this is an
        // archive" the client is entitled to.
        const tree = Tree.of(rows);
        const inner = tree.at('x64/inner.rpf');
        assert.equal(inner?.kind, 'archive');
        assert.ok(inner && isDirectory(inner));
        assert.deepEqual(
            tree.childrenOf('x64/inner.rpf').map((node) => node.name),
            ['data'],
        );
    });

    it('keeps a plain entry a file', () => {
        const tree = Tree.of(rows);
        assert.equal(tree.at('readme.txt')?.kind, 'binary');
        assert.equal(tree.at('readme.txt')?.len, 2);
        assert.equal(tree.at('art.yft')?.kind, 'resource');
        assert.equal(tree.at('art.yft')?.len, 512);
    });

    it('keeps an empty directory, which a tree of files loses', () => {
        const tree = Tree.of(rows);
        assert.equal(tree.at('empty')?.kind, 'directory');
        assert.deepEqual(tree.childrenOf('empty'), []);
    });

    it('answers nothing for a path the archive does not hold', () => {
        const tree = Tree.of(rows);
        assert.equal(tree.at('nowhere/at/all'), undefined);
        assert.equal(tree.at('readme.txt/deeper'), undefined);
    });

    it('has a root that holds the top of the archive', () => {
        const tree = Tree.of(rows);
        assert.deepEqual(
            tree.childrenOf('').map((node) => node.name).sort(),
            ['art.yft', 'empty', 'readme.txt', 'x64'],
        );
    });

    it('does not depend on the order the rows arrive in', () => {
        const shuffled = [...rows].reverse();
        assert.equal(Tree.of(shuffled).at('x64/inner.rpf')?.kind, 'archive');
        assert.equal(Tree.of(shuffled).at('x64/inner.rpf/data/vehicles.meta')?.len, 11);
    });

    it('lists every file through the nesting', () => {
        assert.deepEqual(
            Tree.of(rows).files().map((node) => node.path).sort(),
            ['art.yft', 'readme.txt', 'x64/inner.rpf/data/vehicles.meta'],
        );
    });
});
