/**
 * Every failure category, produced by the daemon itself rather than described.
 *
 * R7.6 is only as good as the mapping, and the mapping is only worth anything
 * if the numbers it keys off are the numbers the daemon really sends. So each
 * case here makes the daemon fail for real and checks what a user would be
 * told. DR-010.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { Daemon } from '../src/core/daemon.js';
import { DaemonError, EXIT, PROTOCOL, advise, render } from '../src/core/errors.js';
import type { Opened } from '../src/core/protocol.js';
import { SKIP, binary, packArchive, scratch } from './support.js';

describe('what the daemon actually answers with', { skip: SKIP }, () => {
    const dir = scratch('failures');
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

    /** The failure a call produced, insisting there was one. */
    async function failing(work: Promise<unknown>): Promise<DaemonError> {
        const outcome = await work.then(
            () => undefined,
            (error: unknown) => error,
        );
        assert.ok(outcome instanceof DaemonError, `expected a failure, got ${String(outcome)}`);
        return outcome;
    }

    async function ordinary(name: string): Promise<string> {
        return packArchive(path.join(dir, `${name}.rpf`), {
            entries: [{ path: 'data/greeting.txt', bytes: Buffer.from('hello there') }],
        });
    }

    it('answers 3 for a path the archive does not hold, and says how paths are spelt', async () => {
        const daemon = start();
        await daemon.request<Opened>('open', { path: await ordinary('absent') });
        const failure = await failing(daemon.request('read', { handle: 1, path: 'data/nope.txt' }));
        assert.equal(failure.code, EXIT.notFound);
        assert.equal(advise(failure).kind, 'not-found');
    });

    it('carries the daemon\'s own separator diagnostic through to the user', async () => {
        // DR-016: `\` is an ordinary character in an entry name, so a path
        // holding one is a genuine not-found — and the answer is the rule plus
        // the caller's own path respelt. The client must not swallow that.
        const daemon = start();
        await daemon.request<Opened>('open', { path: await ordinary('separator') });
        const failure = await failing(
            daemon.request('read', { handle: 1, path: 'data\\greeting.txt' }),
        );
        assert.equal(failure.code, EXIT.notFound);
        const advice = advise(failure);
        assert.match(advice.reason, /data\/greeting\.txt/, advice.reason);
        assert.match(render(advice), /separates with \//);
    });

    it('answers 6 for bytes that claim to be nothing', async () => {
        // DR-019: what the first four bytes claim decides who has to act.
        // These claim nothing, so the request named something that is not an
        // archive and the caller is the one who has to change — the advice
        // must say the archive is fine, because it is.
        const at = path.join(dir, 'garbage.rpf');
        fs.writeFileSync(at, Buffer.alloc(4096));
        const failure = await failing(start().request('open', { path: at }));
        assert.equal(failure.code, EXIT.refused);
        const advice = advise(failure);
        assert.equal(advice.kind, 'refused');
        assert.match(advice.action, /Nothing is wrong with the archive/);
    });

    it('answers 4 for bytes that claim a container and are not one', async () => {
        // The other half of DR-019, and the half that is genuinely the
        // archive's fault: the magic names RPF7 and the header stops short.
        const whole = fs.readFileSync(await ordinary('truncated'));
        const at = path.join(dir, 'truncated.rpf');
        fs.writeFileSync(at, whole.subarray(0, 8));
        const failure = await failing(start().request('open', { path: at }));
        assert.equal(failure.code, EXIT.corrupt);
        const advice = advise(failure);
        assert.equal(advice.kind, 'corrupt');
        assert.match(advice.action, /Nothing you supply/);
    });

    it('answers 5 for an archive whose encryption tag is not OPEN', async () => {
        // The tag is the u32 at offset 12 of the header, and anything but OPEN
        // is refused at parse with a variant of its own: "cannot open this" is
        // kept apart from "this is broken". R6.3.
        const at = await ordinary('encrypted');
        const bytes = fs.readFileSync(at);
        bytes.writeUInt32LE(0x0ffffff9, 12);
        fs.writeFileSync(at, bytes);

        const failure = await failing(start().request('open', { path: at }));
        assert.equal(failure.code, EXIT.needsKey);
        const advice = advise(failure);
        assert.equal(advice.kind, 'needs-key');
        assert.match(advice.action, /never bundles keys/);
    });

    it('answers 9 for an archive of a version this build has no codec for', async () => {
        const at = path.join(dir, 'rpf2.rpf');
        const bytes = Buffer.alloc(4096);
        bytes.write('RPF2', 0, 'ascii');
        fs.writeFileSync(at, bytes);

        const failure = await failing(start().request('open', { path: at }));
        assert.equal(failure.code, EXIT.unsupported, failure.reason);
        const advice = advise(failure);
        assert.equal(advice.kind, 'unsupported');
        assert.match(advice.action, /the missing part is here/);
    });

    it('answers 7 for a path that is not there at all', async () => {
        const failure = await failing(
            start().request('open', { path: path.join(dir, 'no-such-file.rpf') }),
        );
        assert.equal(failure.code, EXIT.io);
        assert.equal(advise(failure).kind, 'io');
    });

    it('answers 6 for a filesystem path that runs on past an archive', async () => {
        // An in-archive path spelled as a filesystem one is a request the tool
        // does not accept, not a disk that misbehaved. DR-009's narrowing.
        const at = await ordinary('past');
        const failure = await failing(
            start().request('open', { path: path.join(at, 'data/greeting.txt') }),
        );
        assert.equal(failure.code, EXIT.refused, failure.reason);
        assert.equal(advise(failure).kind, 'refused');
    });

    it('answers below zero when the request did not follow the protocol', async () => {
        const daemon = start();
        assert.equal((await failing(daemon.request('nonesuch'))).code, PROTOCOL.methodNotFound);
        assert.equal(
            (await failing(daemon.request('open', { path: 7 }))).code,
            PROTOCOL.invalidParams,
        );
        const advice = advise(await failing(daemon.request('nonesuch')));
        assert.equal(advice.kind, 'protocol');
        assert.match(advice.action, /fault in the extension/);
    });

    it('never renders a failure as a stack trace', async () => {
        const daemon = start();
        for (const work of [
            daemon.request('open', { path: path.join(dir, 'gone.rpf') }),
            daemon.request('nonesuch'),
            daemon.request('read', { handle: 44, path: 'x' }),
        ]) {
            const shown = render(advise(await failing(work)));
            assert.ok(!shown.includes('    at '), shown);
            assert.ok(shown.split('\n').length >= 3, shown);
        }
    });
});
