/**
 * The client against a real `rpf serve --stdio`, built from this repository.
 *
 * Not a mock: the only evidence that this client and the daemon agree is that
 * they were made to talk to each other.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import { Daemon } from '../src/core/daemon.js';
import { DaemonError, EXIT, PROTOCOL, TransportError } from '../src/core/errors.js';
import type { Listed, Opened, Progress, ReadEntry } from '../src/core/protocol.js';
import { SKIP, binary, incompressible, packArchive, resourceBytes, scratch } from './support.js';

describe('the daemon client', { skip: SKIP }, () => {
    const dir = scratch('daemon');
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

    async function simple(name: string): Promise<string> {
        return packArchive(path.join(dir, `${name}.rpf`), {
            entries: [
                { path: 'data/greeting.txt', bytes: Buffer.from('hello there') },
                { path: 'art.yft', bytes: resourceBytes(), class: 'resource', storage: 'stored' },
            ],
        });
    }

    it('opens an archive and reads an entry back whole', async () => {
        const daemon = start();
        const archive = await simple('open');
        const opened = await daemon.request<Opened>('open', { path: archive });
        assert.equal(opened.handle, 1);
        assert.equal(opened.path, fs.realpathSync(archive), 'open reports the resolved path');
        assert.ok(opened.entries > 0);

        const entry = await daemon.request<ReadEntry>('read', {
            handle: opened.handle,
            path: 'data/greeting.txt',
        });
        assert.equal(entry.pending, false);
        assert.equal(Buffer.from(entry.bytes, 'base64').toString(), 'hello there');
    });

    it('correlates by id when a cancel answer overtakes a response', async () => {
        // A cancel is answered on the daemon's reading thread without waiting
        // its turn, so a response can arrive before one sent earlier. DR-008.
        const daemon = start();
        const archive = await simple('overtake');
        await daemon.request<Opened>('open', { path: archive });
        const listing = daemon.send<Listed[]>('list', { handle: 1, recursive: true });
        const cancel = daemon.cancel(9999);
        const [rows, answer] = await Promise.all([listing.result, cancel]);
        assert.ok(rows.length > 0);
        assert.equal(answer.cancelling, false);
        assert.equal(answer.running, null, 'nothing was running');
    });

    it('reads past progress notifications and still finds its response', async () => {
        const archive = path.join(dir, 'bulk.rpf');
        await packArchive(archive, {
            entries: Array.from({ length: 8 }, (_, at) => ({
                path: `bulk/${String(at).padStart(2, '0')}.bin`,
                bytes: incompressible(64 * 1024),
            })),
        });
        const daemon = start();
        await daemon.request<Opened>('open', { path: archive });
        await daemon.request('write', {
            handle: 1,
            path: 'bulk/00.bin',
            bytes: Buffer.from('replaced').toString('base64'),
        });

        const seen: Progress[] = [];
        const commit = daemon.send<{ method: string }>(
            'commit',
            { handle: 1, rebuild: true },
            (progress) => seen.push(progress),
        );
        const answer = await commit.result;
        assert.equal(answer.method, 'rebuild');
        assert.ok(seen.length > 0, 'a rebuild reported no progress');
        assert.equal(daemon.unroutedProgress, 0, 'a notification named work this client did not start');
        for (const step of seen) {
            assert.equal(step.handle, 1);
            assert.ok(step.total > 0);
            assert.ok(step.done >= 1 && step.done <= step.total);
            assert.equal(typeof step.skipped, 'number');
        }
    });

    it('stops a rebuild it started, by naming the request that started it', async () => {
        // A cancel that names nothing means "whatever is running", which is
        // somebody else's commit as readily as this one. DR-008.
        const archive = path.join(dir, 'cancel.rpf');
        await packArchive(archive, {
            entries: Array.from({ length: 16 }, (_, at) => ({
                path: `bulk/${String(at).padStart(2, '0')}.bin`,
                bytes: incompressible(512 * 1024),
            })),
        });
        const before = fs.readFileSync(archive);
        const daemon = start();
        await daemon.request<Opened>('open', { path: archive });
        await daemon.request('write', {
            handle: 1,
            path: 'bulk/00.bin',
            bytes: Buffer.from('replaced').toString('base64'),
        });

        let settled = false;
        const commit = daemon.send('commit', { handle: 1, rebuild: true }, () => {
            if (!settled) {
                void commit.cancel();
            }
        });
        const failure = await commit.result.then(
            () => undefined,
            (error: unknown) => error,
        );
        settled = true;
        assert.ok(failure instanceof DaemonError, `expected a refusal, got ${String(failure)}`);
        assert.equal(failure.code, EXIT.cancelled, failure.message);
        assert.deepEqual(
            fs.readFileSync(archive),
            before,
            'a cancelled rebuild left something behind',
        );
    });

    it('keeps two numbering schemes apart: protocol below zero, exit codes above', async () => {
        const daemon = start();
        const archive = await simple('codes');
        await daemon.request<Opened>('open', { path: archive });

        const unknown = await daemon.request('nonesuch').catch((error: unknown) => error);
        assert.ok(unknown instanceof DaemonError);
        assert.equal(unknown.code, PROTOCOL.methodNotFound);

        const missing = await daemon
            .request('read', { handle: 99, path: 'x' })
            .catch((error: unknown) => error);
        assert.ok(missing instanceof DaemonError);
        assert.equal(missing.code, EXIT.refused, 'a handle that was never opened is a refusal');

        const illTyped = await daemon
            .request('read', { handle: 1 })
            .catch((error: unknown) => error);
        assert.ok(illTyped instanceof DaemonError);
        assert.equal(illTyped.code, PROTOCOL.invalidParams);
    });

    it('carries an entry far bigger than one pipe chunk in each direction', async () => {
        const payload = incompressible(4 * 1024 * 1024);
        const archive = path.join(dir, 'big.rpf');
        await packArchive(archive, {
            entries: [{ path: 'big.bin', bytes: payload, storage: 'stored' }],
        });
        const daemon = start();
        await daemon.request<Opened>('open', { path: archive });
        const entry = await daemon.request<ReadEntry>('read', { handle: 1, path: 'big.bin' });
        assert.deepEqual(Buffer.from(entry.bytes, 'base64'), payload);

        const replacement = incompressible(4 * 1024 * 1024);
        await daemon.request('write', {
            handle: 1,
            path: 'big.bin',
            bytes: replacement.toString('base64'),
        });
        const back = await daemon.request<ReadEntry>('read', { handle: 1, path: 'big.bin' });
        assert.equal(back.pending, true, 'a read should see the buffer');
        assert.deepEqual(Buffer.from(back.bytes, 'base64'), replacement);
    });

    it('fails every request in flight when the daemon goes, rather than hanging', async () => {
        const daemon = Daemon.start({ binary: binary() });
        const archive = await simple('gone');
        await daemon.request<Opened>('open', { path: archive });
        const code = await daemon.dispose();
        assert.equal(code, 0, 'a daemon whose standard input ends exits cleanly');
        const failure = await daemon.request('list', { handle: 1 }).catch((error: unknown) => error);
        assert.ok(failure instanceof TransportError, `expected a transport failure: ${String(failure)}`);
    });

    it('settles its exit promise when the process goes, so a client can recover', async () => {
        // DR-002 makes process lifetime the client's problem, and every handle
        // the daemon issued goes with it.
        const daemon = Daemon.start({ binary: binary() });
        const archive = await simple('exit');
        await daemon.request<Opened>('open', { path: archive });
        const exited = daemon.exited;
        await daemon.dispose();
        assert.equal(await exited, 0);
        assert.equal(daemon.running, false);
    });

    it('says the binary is not a daemon rather than waiting on one', async () => {
        const daemon = Daemon.start({ binary: path.join(dir, 'no-such-binary') });
        const failure = await daemon.request('open', { path: 'x' }).catch((error: unknown) => error);
        assert.ok(failure instanceof TransportError, String(failure));
        await daemon.dispose();
    });
});
