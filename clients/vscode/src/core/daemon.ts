/**
 * A client for `rpf serve --stdio`. DR-002.
 *
 * What the daemon requires of whoever talks to it, and where each of these is
 * answered here:
 *
 * - **Objects with no `id` arrive before the response to a request.** They are
 *   progress notifications, and a client reads past them looking for the `id`
 *   it sent. DR-008.
 * - **Progress is lossy.** At most 64 notifications may be queued before
 *   further ones are dropped, and the next one that gets through carries
 *   `skipped`. Nothing is computed here from how many arrived.
 * - **A cancel overtakes.** It is answered on the daemon's reading thread
 *   without waiting its turn, so a response can arrive out of order and
 *   correlation is by `id` rather than by position.
 * - **Standard output must keep being read.** A client that takes less than
 *   about four kilobytes a second cannot be told from one that has gone, and
 *   is cut off. So the `data` handler here never stops consuming, and nothing
 *   in this file waits on anything while holding the stream.
 *
 * It holds no archive knowledge: `docs/conventions.md` §1.
 */

import { type ChildProcessWithoutNullStreams, spawn } from 'node:child_process';

import { DaemonError, TransportError } from './errors.js';
import { LineDecoder } from './framing.js';
import type { Cancelled, Json, Progress, RequestId } from './protocol.js';

/** How much of standard error is kept for a diagnostic. */
const DIAGNOSTICS_KEPT = 8 * 1024;

/** How long a daemon is given to exit on its own before it is killed. */
const SHUTDOWN_GRACE_MS = 5000;

/** How to start one. */
export interface DaemonOptions {
    /** The `rpf` binary. */
    binary: string;
    /** Where the daemon runs, which is what a relative path resolves against. */
    cwd?: string;
    /** Every line the daemon writes, for a log the user can be shown. */
    onLog?: (line: string) => void;
}

/** One request in flight, and the `id` a cancel would name it by. */
export interface Call<T> {
    /** The `id` sent, which is the only name a client has for the work. */
    readonly id: RequestId;
    /** What the daemon answered, or the failure it answered with. */
    readonly result: Promise<T>;
    /** Asks the daemon to stop it, naming it by this call's own `id`. */
    cancel(): Promise<Cancelled>;
}

/** A request waiting for its response. */
interface Waiting {
    method: string;
    settle: (value: Json) => void;
    fail: (failure: Error) => void;
    onProgress?: (progress: Progress) => void;
}

/** A long-lived `rpf serve --stdio` process. */
export class Daemon {
    private readonly child: ChildProcessWithoutNullStreams;
    private readonly decoder = new LineDecoder();
    private readonly waiting = new Map<RequestId, Waiting>();
    private readonly onLog: ((line: string) => void) | undefined;
    private diagnostics = '';
    private nextId = 0;
    private ended: TransportError | undefined;
    private unrouted = 0;
    private writes: Promise<void> = Promise.resolve();
    private readonly finished: Promise<number | null>;

    private constructor(options: DaemonOptions) {
        this.onLog = options.onLog;
        const spawned: { cwd?: string } = {};
        if (options.cwd !== undefined) {
            spawned.cwd = options.cwd;
        }
        this.child = spawn(options.binary, ['serve', '--stdio'], {
            ...spawned,
            stdio: ['pipe', 'pipe', 'pipe'],
        });

        this.child.stdout.on('data', (chunk: Buffer) => {
            for (const line of this.decoder.push(chunk)) {
                this.receive(line);
            }
        });
        this.child.stderr.on('data', (chunk: Buffer) => {
            this.diagnostics = (this.diagnostics + chunk.toString('utf8')).slice(-DIAGNOSTICS_KEPT);
        });
        // A pipe the daemon closed is not an exception here: the exit that
        // follows is what every waiting request is failed with.
        this.child.stdin.on('error', () => undefined);

        this.finished = new Promise((settle) => {
            this.child.on('exit', (code) => {
                this.stop(
                    new TransportError(
                        `the rpf daemon exited with code ${code ?? 'unknown'}`,
                        this.diagnostics,
                    ),
                );
                settle(code);
            });
            this.child.on('error', (failure) => {
                this.stop(
                    new TransportError(
                        `the rpf daemon could not be started: ${failure.message}`,
                        this.diagnostics,
                    ),
                );
                settle(null);
            });
        });
    }

    /** Starts one. It is running as soon as this returns. */
    static start(options: DaemonOptions): Daemon {
        return new Daemon(options);
    }

    /** Whether the process is still there. */
    get running(): boolean {
        return this.ended === undefined;
    }

    /**
     * Settles when the process has gone, with whatever it exited with.
     *
     * DR-002 makes process lifetime and crash recovery the client's problem,
     * and this is what a client watches to notice. Every handle the daemon
     * issued goes with it, buffered edits included.
     */
    get exited(): Promise<number | null> {
        return this.finished;
    }

    /** Whatever the daemon has written to standard error. */
    get stderr(): string {
        return this.diagnostics;
    }

    /**
     * Progress notifications that named a request this client is not waiting
     * for.
     *
     * Zero in every ordinary run: the ids sent here are small numbers, which
     * DR-008's third amendment echoes back whole. A non-zero count means the
     * daemon named work this client did not start, and it is counted rather
     * than guessed at.
     */
    get unroutedProgress(): number {
        return this.unrouted;
    }

    /** Sends one request, and gives back the `id` a cancel would name it by. */
    send<T>(
        method: string,
        params?: Record<string, Json>,
        onProgress?: (progress: Progress) => void,
    ): Call<T> {
        this.nextId += 1;
        const id = this.nextId;
        const result = new Promise<T>((settle, fail) => {
            if (this.ended) {
                fail(this.ended);
                return;
            }
            const waiting: Waiting = {
                method,
                settle: settle as (value: Json) => void,
                fail,
            };
            if (onProgress) {
                waiting.onProgress = onProgress;
            }
            this.waiting.set(id, waiting);
            this.write({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) });
        });
        return {
            id,
            result,
            cancel: () => this.cancel(id),
        };
    }

    /** Sends one request and waits for its answer. */
    request<T>(method: string, params?: Record<string, Json>): Promise<T> {
        return this.send<T>(method, params).result;
    }

    /**
     * Asks the daemon to stop the operation one of this client's requests
     * started.
     *
     * Naming the request rather than nothing: a cancel that names nothing means
     * "whatever is running", which is somebody else's commit as readily as
     * this one. DR-008.
     */
    cancel(target: RequestId, handle?: number): Promise<Cancelled> {
        const params: Record<string, Json> = { request: target };
        if (handle !== undefined) {
            params.handle = handle;
        }
        return this.request<Cancelled>('cancel', params);
    }

    /**
     * Ends standard input and waits for the daemon to go.
     *
     * Standard input ending does not cost a client the answer to a request it
     * already sent — the daemon drains what it has queued for as long as this
     * end keeps reading — so this waits rather than killing at once. DR-008.
     */
    async dispose(): Promise<number | null> {
        if (this.ended) {
            return this.finished;
        }
        this.child.stdin.end();
        const killed = new Promise<void>((wake) => {
            const timer = setTimeout(() => {
                this.child.kill();
                wake();
            }, SHUTDOWN_GRACE_MS);
            void this.finished.then(() => {
                clearTimeout(timer);
                wake();
            });
        });
        await killed;
        return this.finished;
    }

    private write(request: object): void {
        const line = `${JSON.stringify(request)}\n`;
        // Queued rather than written outright: a request carrying a 20 MB
        // payload does not fit the pipe in one go, and the writes have to reach
        // the daemon in the order they were made.
        this.writes = this.writes.then(
            () =>
                new Promise<void>((done) => {
                    if (this.child.stdin.destroyed || this.child.stdin.writableEnded) {
                        done();
                        return;
                    }
                    if (this.child.stdin.write(line)) {
                        done();
                        return;
                    }
                    this.child.stdin.once('drain', done);
                }),
        );
    }

    private receive(line: string): void {
        this.onLog?.(line);
        let message: unknown;
        try {
            message = JSON.parse(line);
        } catch {
            // The framing contract is one JSON object per line, so a line that
            // is not one is a fault of the connection and not of a request.
            this.stop(
                new TransportError(
                    'the rpf daemon wrote a line that is not a JSON object',
                    line.slice(0, 512),
                ),
            );
            return;
        }
        if (typeof message !== 'object' || message === null) {
            return;
        }
        const object = message as Record<string, Json>;
        if (object.id === undefined || object.id === null) {
            this.notified(object);
            return;
        }
        const id = object.id;
        if (typeof id !== 'number') {
            this.unrouted += 1;
            return;
        }
        const waiting = this.waiting.get(id);
        if (!waiting) {
            this.unrouted += 1;
            return;
        }
        this.waiting.delete(id);
        const failure = object.error;
        if (failure && typeof failure === 'object' && !Array.isArray(failure)) {
            const code = typeof failure.code === 'number' ? failure.code : 1;
            const reason = typeof failure.message === 'string' ? failure.message : line;
            waiting.fail(new DaemonError(waiting.method, code, reason, Daemon.nameOf(failure)));
            return;
        }
        waiting.settle(object.result ?? null);
    }

    private notified(object: Record<string, Json>): void {
        if (object.method !== 'progress') {
            return;
        }
        const params = object.params;
        if (!params || typeof params !== 'object' || Array.isArray(params)) {
            return;
        }
        const progress = params as unknown as Progress;
        const named = (params as Record<string, Json>).request;
        // `request` is the whole `id` when it is small and a string describing
        // its size when it is not, and this client only ever sends small
        // numbers — so anything else names work it did not start. DR-008.
        if (typeof named !== 'number') {
            this.unrouted += 1;
            return;
        }
        const waiting = this.waiting.get(named);
        if (!waiting?.onProgress) {
            this.unrouted += 1;
            return;
        }
        waiting.onProgress(progress);
    }

    /**
     * The failure's own name, out of the error object's `data`.
     *
     * Empty when there is none, which this daemon never writes — DR-032 §5 puts
     * it on every error object — and which an older one would. Read here rather
     * than in `errors.ts` because this file is the one that knows the wire's
     * shapes.
     */
    private static nameOf(failure: Record<string, Json>): string {
        const data = failure.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
            return '';
        }
        const reason = (data as Record<string, Json>).reason;
        return typeof reason === 'string' ? reason : '';
    }

    private stop(failure: TransportError): void {
        if (this.ended) {
            return;
        }
        this.ended = failure;
        const abandoned = [...this.waiting.values()];
        this.waiting.clear();
        for (const waiting of abandoned) {
            waiting.fail(failure);
        }
    }
}
