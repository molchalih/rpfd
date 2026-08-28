import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { BadUri, addressOf, join, normalise, rootOf, split, tokenFor, uriOf } from '../src/core/uri.js';

describe('the rpf: scheme', () => {
    it('round-trips an archive and an entry', () => {
        const address = { archive: '/tmp/one/dlc.rpf', inside: 'x64/vehicles.rpf/data/handling.meta' };
        assert.deepEqual(addressOf(uriOf(address)), address);
    });

    it('puts the archive in the query and the entry in the path', () => {
        const uri = uriOf({ archive: '/tmp/dlc.rpf', inside: 'data/x.meta' });
        assert.equal(uri.scheme, 'rpf');
        assert.equal(uri.query, '/tmp/dlc.rpf');
        assert.equal(uri.path, '/data/x.meta');
        assert.equal(uri.authority, tokenFor('/tmp/dlc.rpf'));
    });

    it('gives an archive root a path an editor can join children onto', () => {
        const root = rootOf('/tmp/dlc.rpf');
        assert.equal(root.path, '/');
        assert.deepEqual(addressOf(root), { archive: '/tmp/dlc.rpf', inside: '' });
    });

    it('gives two archives two authorities and one archive one', () => {
        assert.notEqual(tokenFor('/tmp/a.rpf'), tokenFor('/tmp/b.rpf'));
        assert.equal(tokenFor('/tmp/a.rpf'), tokenFor('/tmp/a.rpf'));
        assert.match(tokenFor('/tmp/a.rpf'), /^[0-9a-f]{16}$/);
    });

    it('refuses a URI whose two halves name different archives', () => {
        // The authority carries no information of its own, so a mismatch is
        // resolved to neither half rather than to the one that looks likelier.
        const uri = { ...uriOf({ archive: '/tmp/a.rpf', inside: 'x' }), query: '/tmp/b.rpf' };
        assert.throws(() => addressOf(uri), BadUri);
    });

    it('refuses a URI that names no archive at all', () => {
        assert.throws(() => addressOf({ scheme: 'rpf', authority: '', path: '/x', query: '' }), BadUri);
    });

    it('refuses another scheme', () => {
        assert.throws(
            () => addressOf({ scheme: 'file', authority: '', path: '/x', query: '/tmp/a.rpf' }),
            BadUri,
        );
    });

    it('keeps a backslash as a name byte rather than reading it as a separator', () => {
        // DR-016: an archive can hold `x64/evil.txt` and `x64\evil.txt` as two
        // distinct entries, each addressable, so folding one spelling into the
        // other would make an entry `ls` prints unreadable by `cat`.
        const address = { archive: '/tmp/a.rpf', inside: 'x64\\evil.txt' };
        const back = addressOf(uriOf(address));
        assert.equal(back.inside, 'x64\\evil.txt');
        assert.deepEqual(split('x64\\evil.txt'), { parent: '', name: 'x64\\evil.txt' });
    });

    it('refuses a path that climbs out of the archive', () => {
        for (const climbing of ['..', 'a/../b', 'a/./b', 'a//b']) {
            assert.throws(() => normalise(climbing), BadUri, climbing);
        }
    });

    it('reads a leading and a trailing separator off a path', () => {
        assert.equal(normalise('/data/x.meta'), 'data/x.meta');
        assert.equal(normalise('data/'), 'data');
        assert.equal(normalise('/'), '');
        assert.equal(normalise(''), '');
    });

    it('joins and splits the way the daemon spells a path', () => {
        assert.equal(join('', 'a.txt'), 'a.txt');
        assert.equal(join('x64', 'inner.rpf'), 'x64/inner.rpf');
        assert.equal(join('/x64/', '/inner.rpf/'), 'x64/inner.rpf');
        assert.deepEqual(split('x64/inner.rpf/art.yft'), {
            parent: 'x64/inner.rpf',
            name: 'art.yft',
        });
        assert.deepEqual(split(''), { parent: '', name: '' });
    });
});
