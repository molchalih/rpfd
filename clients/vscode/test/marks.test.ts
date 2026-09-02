/**
 * The badge a buffered change wears in the explorer. R7.7.
 *
 * The provider that shows it needs a running editor; the mapping does not, and
 * this is the half that says which change is which letter.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { Pending } from '../src/core/pending.js';
import { markOf } from '../src/vscode/marks.js';

describe('the badge on a buffered change', () => {
    function marks(pending: Pending): Record<string, string> {
        return Object.fromEntries(pending.shown().map((one) => [one.path, markOf(one).badge]));
    }

    it('is the letter git uses for the same change', () => {
        const pending = new Pending();
        const bytes = new Uint8Array([1]);
        pending.apply(pending.plan('a.txt', 'a.txt', { kind: 'write', contents: bytes, create: false }));
        pending.apply(pending.plan('new.txt', 'new.txt', { kind: 'write', contents: bytes, create: true }));
        pending.apply(pending.plan('gone.txt', 'gone.txt', { kind: 'remove', recursive: false }));
        pending.apply(pending.plan('old', 'old', { kind: 'rename', to: 'fresh' }));
        pending.apply(pending.plan('made', 'made', { kind: 'mkdir' }));

        assert.deepEqual(marks(pending), {
            'a.txt': 'M',
            'new.txt': 'A',
            'gone.txt': 'D',
            fresh: 'R',
            made: 'A',
        });
    });

    it('carries a colour this extension contributes, never a hardcoded one', () => {
        const pending = new Pending();
        pending.apply(pending.plan('a.txt', 'a.txt', { kind: 'rename', to: 'b.txt' }));
        const [one] = pending.shown();
        assert.ok(one);
        assert.equal(markOf(one).color, 'rpf.renamedResourceForeground');
        assert.match(markOf(one).tooltip, /Renamed from a\.txt/);
    });

    it('shows an edit under a renamed folder where the user sees it', () => {
        const pending = new Pending();
        pending.apply(pending.plan('data', 'data', { kind: 'rename', to: 'info' }));
        pending.apply(
            pending.plan('data/one.txt', 'info/one.txt', {
                kind: 'write',
                contents: new Uint8Array([2]),
                create: false,
            }),
        );
        assert.deepEqual(marks(pending), { info: 'R', 'info/one.txt': 'M' });
    });
});
