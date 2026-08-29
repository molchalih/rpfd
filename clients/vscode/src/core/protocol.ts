/**
 * The shapes on the wire, as `crates/rpf/src/serve.rs` writes them.
 *
 * Declarations only: nothing here parses an archive, and nothing here decides
 * anything. `docs/conventions.md` §1 — the client is a transport and an
 * editor-API adapter.
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
    /** Negative is JSON-RPC's own; positive is the exit code. DR-008, DR-010. */
    code: number;
    message: string;
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
 * `request` is the `id` of the request that started the work when that `id` is
 * small, and a string describing its size when it is not — DR-008's third
 * amendment. `handle` is `null` for a `pack`, which has no session — DR-014.
 * Notifications are dropped when the client is behind, so `skipped` says how
 * many, and nothing may be computed from how many arrived.
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

/** What `read` answers. */
export interface ReadEntry {
    path: string;
    len: number;
    /** Whether these bytes are a buffered edit rather than what is on disk. */
    pending: boolean;
    bytes: string;
}

/**
 * What `write`, `delete` and `mkdir` answer. One shape for every method that
 * buffers a change, so a client reads one answer. DR-026.
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
 * A structural change is always a rebuild — an entry added or removed moves the
 * entry table, which moves the names blob, which moves the floor every payload
 * sits above — and the verdict is reached for the whole set before anything is
 * compressed. DR-026.
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

/** What `verify` answers, whatever it finds. DR-008's fourth amendment. */
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
