/**
 * The shapes on the wire, as `crates/rpf/src/serve.rs` writes them.
 *
 * Declarations only: nothing here parses an archive or decides anything.
 */

/** A JSON value, as the wire carries one. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** What a request's `id` may be. This client only ever sends a number. */
export type RequestId = number;

/** One request, framed as the daemon reads it. */
export interface Request {
    jsonrpc: '2.0';
    id?: RequestId;
    method: string;
    params?: Record<string, Json>;
}

/** The error object a rejected call answers with. */
export interface WireError {
    /** Negative is JSON-RPC's own; positive is the exit code. */
    code: number;
    message: string;
    /**
     * Where the protocol puts anything more than a code and a sentence.
     *
     * `reason` is the failure's own name, on every error object the daemon
     * writes. It is a finer classification within a code and never a
     * replacement for one: the number is the contract.
     */
    data?: { reason?: string };
}

/** One response. */
export interface Response {
    jsonrpc: '2.0';
    id: RequestId | null;
    result?: Json;
    error?: WireError;
}

/**
 * One progress notification: an object with a `method` and no `id`.
 *
 * `request` is the starting request's `id` when that `id` is small, and a
 * string describing its size when it is not; `handle` is `null` for a `pack`,
 * which has no session. Notifications are dropped when the client is behind, so
 * nothing may be computed from how many arrived.
 */
export interface Progress {
    handle: number | null;
    request: Json;
    path: string;
    done: number;
    total: number;
    bytes: number;
    skipped: number;
}

/** What `open` answers. The path is the resolved one, not the one asked for. */
export interface Opened {
    handle: number;
    path: string;
    entries: number;
    len: number;
}

/** One row of a listing, as `rpf --json ls` prints the same row. */
export interface Listed {
    path: string;
    kind: 'directory' | 'binary' | 'resource';
    /** A file's length, or a directory's child count. */
    len: number;
}

/** Which form of an entry a request asks for, and an answer came back in. */
export type ViewName = 'raw' | 'xml' | 'auto';

/** What `read` answers. */
export interface ReadEntry {
    path: string;
    len: number;
    /** Whether these bytes are a buffered edit rather than what is on disk. */
    pending: boolean;
    /**
     * Which form these bytes are: the entry's own, or its XML view.
     *
     * Never `'auto'` — that is a question and not an answer.
     */
    as: Exclude<ViewName, 'auto'>;
    /**
     * What the entry's payload announces itself to be, and `null` when it
     * announces nothing or was not read.
     *
     * **This is the only thing a client may decide a presentation from.** An
     * extension is not evidence: a `.ymt` is `PSO` in some archives, `RBF` in
     * others and a resource in most.
     */
    encoding: 'xml' | 'text' | 'rbf' | 'pso' | null;
    bytes: string;
}

/**
 * What `write`, `delete` and `mkdir` answer. One shape for every method that
 * buffers a change, so a client reads one answer.
 */
export interface Wrote {
    path: string;
    /** The payload's length, and `null` for a change that carries none. */
    len: number | null;
    /** How many changes are now buffered in the session. */
    pending: number;
}

/** What `rename` answers. */
export interface Renamed {
    from: string;
    to: string;
    pending: number;
}

/**
 * One change no in-place patch can express, and what it does.
 *
 * A structural change is always a rebuild, and the verdict is reached for the
 * whole set before anything is compressed.
 */
export interface Structural {
    path: string;
    /** What the change does that no patch can, in the library's own words. */
    structural: string;
}

/** What `commit` answers when there was something to commit. */
export interface Committed {
    committed: number;
    method?: 'patch' | 'rebuild';
    entries?: number;
    len?: number;
    unchanged?: boolean;
    dry_run?: boolean;
    planned?: { path: string; at: number; len: number; allocation: number }[];
    rejected?: { path: string; needed: number; allocation: number }[];
    structural?: Structural[];
}

/** What `verify` answers, whatever it finds. */
export interface Verified {
    path: string;
    entries_checked: number;
    problems: { path: string; reason: string }[];
}

/** What `info` answers. */
export interface Summary {
    path: string;
    inside: string;
    len: number;
    encryption: string;
    entries: number;
    directories: number;
    binary_files: number;
    resource_files: number;
    nested_archives: number;
    unreferenced_bytes: number;
}

/** What `extract` answers. */
export interface Extracted {
    archive: string;
    into: string;
    files: number;
    directories: number;
    manifest: string;
}

/** What `pack` answers. */
export interface Packed {
    archive: string;
    entries: number;
    len: number;
}

/** What `cancel` answers. */
export interface Cancelled {
    cancelling: boolean;
    running: 'commit' | 'patch' | 'rebuild' | 'verify' | 'extract' | 'pack' | null;
    request?: Json;
    handle?: number | null;
    reason?: string;
}

/** What `close` answers. */
export interface Closed {
    closed: boolean;
    /** Buffered edits that went with the session. */
    discarded: number;
}

/** What `pending` answers. */
export interface Pending {
    paths: string[];
}

/** What `discard` answers. */
export interface Discarded {
    discarded: number;
}

/**
 * What `forget` answers: one change out of the buffer, and what is left.
 *
 * `forgotten` is false for a path nothing was buffered at, which is not a
 * failure; `paths` says what is there either way.
 */
export interface Forgotten {
    path: string;
    forgotten: boolean;
    pending: number;
    paths: string[];
}
