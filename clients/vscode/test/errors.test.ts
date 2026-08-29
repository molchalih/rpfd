import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
    DaemonError,
    EXIT,
    type FileSystemWord,
    type Kind,
    PROTOCOL,
    Refused,
    TransportError,
    advise,
    fileSystemWordFor,
    kindOf,
    render,
} from '../src/core/errors.js';

describe('what a failure means', () => {
    it('gives every exit code its own kind, and none of them a wildcard', () => {
        // DR-010 makes the number the contract, so the numbers are written out
        // here rather than derived from the table they are checked against.
        const expected: [number, Kind][] = [
            [1, 'internal'],
            [2, 'usage'],
            [3, 'not-found'],
            [4, 'corrupt'],
            [5, 'needs-key'],
            [6, 'refused'],
            [7, 'io'],
            [8, 'cancelled'],
            [9, 'unsupported'],
        ];
        for (const [code, kind] of expected) {
            assert.equal(kindOf(code), kind, `exit ${code}`);
        }
        assert.equal(kindOf(10), 'unknown', 'a code from a newer daemon');
    });

    it('reads every negative code as the protocol failure it is', () => {
        for (const code of Object.values(PROTOCOL)) {
            assert.equal(kindOf(code), 'protocol', String(code));
        }
    });

    it('tells the user what to do, not what the code was doing', () => {
        const advice = advise(new DaemonError('open', EXIT.needsKey, 'archive is encrypted'));
        assert.equal(advice.kind, 'needs-key');
        assert.match(advice.action, /never bundles keys/);
        assert.equal(advice.reason, 'archive is encrypted');
        assert.match(render(advice), /archive is encrypted/);
    });

    it('says a refused write is the request and not the archive', () => {
        const advice = advise(
            new DaemonError('write', EXIT.refused, 'art.yft is a resource entry; its payload must begin with RSC7'),
        );
        assert.equal(advice.kind, 'refused');
        assert.match(advice.action, /Nothing is wrong with the archive/);
        assert.match(advice.reason, /RSC7/);
    });

    it('says a corrupt archive is nobody\'s input to fix', () => {
        const advice = advise(new DaemonError('read', EXIT.corrupt, 'entry 3 does not inflate'));
        assert.equal(advice.kind, 'corrupt');
        assert.match(advice.action, /Nothing you supply/);
    });

    it('says an unsupported version is this build\'s gap and not the holder\'s', () => {
        const advice = advise(new DaemonError('open', EXIT.unsupported, 'RPF2 archive at offset 0'));
        assert.equal(advice.kind, 'unsupported');
        assert.match(advice.action, /the missing part is here/);
    });

    it('blames the extension for a protocol failure rather than the archive', () => {
        const advice = advise(new DaemonError('nope', PROTOCOL.methodNotFound, 'no method "nope"'));
        assert.equal(advice.kind, 'protocol');
        assert.match(advice.action, /fault in the extension/);
    });

    it('keeps a dead daemon apart from a refused request', () => {
        const advice = advise(new TransportError('the rpf daemon exited with code 7', 'boom'));
        assert.equal(advice.kind, 'transport');
        assert.equal(advice.code, null);
        assert.match(advice.reason, /boom/);
    });

    it('does not dress an internal fault up as an archive problem', () => {
        const advice = advise(new TypeError('cannot read properties of undefined'));
        assert.equal(advice.kind, 'internal');
        assert.match(advice.action, /Report it/);
        assert.match(advice.reason, /cannot read properties/);
    });

    it('tells the user a refused change is about what is buffered, not about the archive', () => {
        // A refusal this client decided is not a fault of the daemon and not a
        // fault of the archive, and saying either would send the user looking
        // in the wrong place. R7.6.
        const advice = advise(new Refused('exists', 'a.txt', 'a.txt is already in the archive'));
        assert.equal(advice.kind, 'pending');
        assert.equal(advice.code, null);
        assert.equal(advice.reason, 'a.txt is already in the archive');
        assert.match(advice.action, /Save the archive|discard/);
        assert.ok(!/stack|trace/i.test(render(advice)));
    });

    it('picks the editor filesystem word from the classification, never from the sentence', () => {
        // R7.6's point: an editor shows these in places a notification cannot
        // reach, and the word is what decides which. Checked here rather than
        // in the editor adapter, because the adapter cannot be run without an
        // editor.
        const expected: [unknown, FileSystemWord][] = [
            [new Refused('exists', 'a', 'x'), 'exists'],
            [new Refused('not-found', 'a', 'x'), 'not-found'],
            [new Refused('is-a-directory', 'a', 'x'), 'is-a-directory'],
            [new Refused('refused', 'a', 'x'), 'no-permissions'],
            [new DaemonError('m', EXIT.notFound, 'x'), 'not-found'],
            [new DaemonError('m', EXIT.refused, 'x'), 'no-permissions'],
            [new DaemonError('m', EXIT.io, 'x'), 'unavailable'],
            [new DaemonError('m', EXIT.corrupt, 'x'), 'other'],
            [new TransportError('gone'), 'unavailable'],
            [new Error('a fault of this extension'), 'other'],
        ];
        for (const [failure, word] of expected) {
            assert.equal(fileSystemWordFor(failure), word, String(failure));
        }
    });

    it('gives every kind a headline and an instruction', () => {
        const kinds: Kind[] = [
            'protocol',
            'internal',
            'usage',
            'not-found',
            'corrupt',
            'needs-key',
            'refused',
            'io',
            'cancelled',
            'unsupported',
            'unknown',
        ];
        assert.ok(advise(new Refused('refused', 'a', 'x')).headline.length > 0, 'pending');
        for (const kind of kinds) {
            const code = kind === 'protocol' ? -32600 : codeFor(kind);
            const advice = advise(new DaemonError('m', code, 'because'));
            assert.equal(advice.kind, kind, kind);
            assert.ok(advice.headline.length > 0, kind);
            assert.ok(advice.action.length > 0, kind);
            assert.ok(!/stack|trace|at Object\./i.test(render(advice)), kind);
        }
    });
});

/** The code that produces one kind, for the sweep above. */
function codeFor(kind: Kind): number {
    switch (kind) {
        case 'internal':
            return 1;
        case 'usage':
            return 2;
        case 'not-found':
            return 3;
        case 'corrupt':
            return 4;
        case 'needs-key':
            return 5;
        case 'refused':
            return 6;
        case 'io':
            return 7;
        case 'cancelled':
            return 8;
        case 'unsupported':
            return 9;
        default:
            return 99;
    }
}
