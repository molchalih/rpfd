import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { LineDecoder } from '../src/core/framing.js';

describe('the daemon framing', () => {
    it('cuts one object per line out of whatever the pipe hands over', () => {
        const decoder = new LineDecoder();
        assert.deepEqual(decoder.push(Buffer.from('{"a":1}\n{"b":2}\n')), ['{"a":1}', '{"b":2}']);
    });

    it('holds a line that arrives in pieces until its newline does', () => {
        const decoder = new LineDecoder();
        assert.deepEqual(decoder.push(Buffer.from('{"a":')), []);
        assert.equal(decoder.pending, 5);
        assert.deepEqual(decoder.push(Buffer.from('1}')), []);
        assert.deepEqual(decoder.push(Buffer.from('\n{"b"')), ['{"a":1}']);
        assert.equal(decoder.pending, 4);
    });

    it('joins a multi-byte character split across two chunks', () => {
        // The pipe cuts bytes, not characters, and a name inside an archive is
        // not necessarily ASCII.
        const decoder = new LineDecoder();
        const line = Buffer.from('{"path":"vehículos.meta"}\n', 'utf8');
        const cut = line.indexOf(0xc3) + 1;
        assert.deepEqual(decoder.push(line.subarray(0, cut)), []);
        assert.deepEqual(decoder.push(line.subarray(cut)), ['{"path":"vehículos.meta"}']);
    });

    it('ignores an empty line rather than failing on one', () => {
        const decoder = new LineDecoder();
        assert.deepEqual(decoder.push(Buffer.from('\n\n{"a":1}\n')), ['{"a":1}']);
    });

    it('cuts a line far longer than one chunk', () => {
        // A `read` answers with a whole entry base64-encoded: the sample's
        // nested archive is 83,482,931 bytes on one line.
        const decoder = new LineDecoder();
        const payload = 'x'.repeat(1_000_000);
        const whole = Buffer.from(`"${payload}"\n`);
        const lines: string[] = [];
        for (let at = 0; at < whole.length; at += 65_536) {
            lines.push(...decoder.push(whole.subarray(at, at + 65_536)));
        }
        assert.equal(lines.length, 1);
        assert.equal(lines[0]?.length, payload.length + 2);
    });
});
