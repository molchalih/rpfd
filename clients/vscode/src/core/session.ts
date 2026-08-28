/**
 * One open archive, and the edits held against it. R7.3.
 *
 * **A write is not free.** Saving one entry may patch its payload in place or
 * may rebuild the whole archive, and the daemon decides which for the *set* of
 * buffered edits before it writes any of them — R4.14. So an edit here is
 * buffered rather than saved, and the set is committed by one explicit act.
 * That is what makes a 145 MB archive editable in a loop: the alternative is
 * deciding the question once per keystroke-sized change.
 *
 * **One writer per archive.** DR-009: an archive is open in one session at a
 * time and the second `open` is refused, so this class is the unit a client
 * counts. Nothing here opens an archive twice, and `close` is what releases the
 * claim — a leaked handle locks the daemon out of its own archive for the rest
 * of its life.
 */

import type { Daemon } from './daemon.js';
import type {
    Cancelled,
    Committed,
    Discarded,
    Extracted,
    Listed,
    Opened,
    Progress,
    ReadEntry,
    Summary,
    Verified,
    Wrote,
} from './protocol.js';
import { Tree } from './tree.js';
import { normalise } from './uri.js';

/** Where a session's buffered edits stand. */
export type SaveState = 'clean' | 'dirty' | 'saving';

/** What a save did. */
export interface Saved {
    /** How the archive was written. */
    method: 'patch' | 'rebuild';
    /** How many buffered edits went in. */
    committed: number;
    /** The archive's entry count afterwards. */
    entries: number;
    /** The archive's length afterwards. */
    len: number;
}

/** What a save would do, without doing any of it. R6.7. */
export interface Preview {
    method: 'patch' | 'rebuild';
    /** Where each edit would land, when it would be patched in place. */
    planned: { path: string; at: number; len: number; allocation: number }[];
    /** Which edits do not fit, which is why the whole set would rebuild. */
    rejected: { path: string; needed: number; allocation: number }[];
}

/** How a save was asked for. */
export interface SaveOptions {
    /** Rebuild even when every edit would fit where it is. */
    rebuild?: boolean;
    /** Write into a detected game installation anyway. */
    force?: boolean;
    onProgress?: (progress: Progress) => void;
}

/** Raised when a session is asked to do two incompatible things at once. */
export class SessionBusy extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SessionBusy';
    }
}

/** An archive held open by the daemon, with its buffered edits. */
export class ArchiveSession {
    private readonly daemon: Daemon;
    private readonly opened: Opened;
    private listing: Tree;
    private readonly dirty = new Map<string, number>();
    private saveState: SaveState = 'clean';
    private saving: number | undefined;
    private stamp = Date.now();
    private readonly listeners = new Set<(state: SaveState) => void>();
    private entryCount: number;
    private byteLength: number;

    private constructor(daemon: Daemon, opened: Opened, listing: Tree) {
        this.daemon = daemon;
        this.opened = opened;
        this.listing = listing;
        this.entryCount = opened.entries;
        this.byteLength = opened.len;
    }

    /**
     * Opens an archive and reads its shape once.
     *
     * The path is on the daemon's own filesystem — the one thing a path on this
     * wire has ever meant. DR-014.
     */
    static async open(daemon: Daemon, archive: string): Promise<ArchiveSession> {
        const opened = await daemon.request<Opened>('open', { path: archive });
        const rows = await daemon.request<Listed[]>('list', {
            handle: opened.handle,
            recursive: true,
        });
        return new ArchiveSession(daemon, opened, Tree.of(rows));
    }

    /** The daemon's handle for this archive. */
    get handle(): number {
        return this.opened.handle;
    }

    /**
     * The archive's path as the daemon resolved it.
     *
     * The resolved one rather than the one asked for: it is what the session
     * claimed, and what a refusal of a second `open` will name. DR-009.
     */
    get path(): string {
        return this.opened.path;
    }

    /** How many entries the archive holds. */
    get entries(): number {
        return this.entryCount;
    }

    /** How long the archive is, in bytes. */
    get len(): number {
        return this.byteLength;
    }

    /** Where the buffered edits stand. */
    get state(): SaveState {
        return this.saveState;
    }

    /** The archive's shape, as of the last listing. */
    get tree(): Tree {
        return this.listing;
    }

    /** Which entries have been edited and not yet saved. */
    dirtyPaths(): string[] {
        return [...this.dirty.keys()];
    }

    /** The length an entry will have once the edits are saved. */
    lengthOf(inside: string): number | undefined {
        const path = normalise(inside);
        const buffered = this.dirty.get(path);
        if (buffered !== undefined) {
            return buffered;
        }
        return this.listing.at(path)?.len;
    }

    /** When this session last changed, for a file's modification time. */
    get changedAt(): number {
        return this.stamp;
    }

    /** Told whenever the buffered edits change state. */
    onStateChange(listener: (state: SaveState) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    /**
     * One entry's bytes: the buffered edit when there is one, and what is on
     * disk otherwise.
     */
    async read(inside: string): Promise<Uint8Array> {
        const answer = await this.daemon.request<ReadEntry>('read', {
            handle: this.handle,
            path: normalise(inside),
        });
        return Buffer.from(answer.bytes, 'base64');
    }

    /**
     * Buffers an edit. Nothing on disk changes until {@link save}.
     *
     * The daemon resolves the path and checks the payload now rather than at
     * commit, so a refusal — a directory, or a payload that is not the `RSC7`
     * a resource entry takes — arrives while the user can still act on it.
     */
    async write(inside: string, bytes: Uint8Array): Promise<void> {
        const path = normalise(inside);
        const answer = await this.daemon.request<Wrote>('write', {
            handle: this.handle,
            path,
            bytes: Buffer.from(bytes).toString('base64'),
        });
        this.dirty.set(path, answer.len);
        this.touch('dirty');
    }

    /** Drops every buffered edit, on both sides. */
    async discard(): Promise<number> {
        if (this.saveState === 'saving') {
            throw new SessionBusy('the archive is being saved; cancel that first');
        }
        const answer = await this.daemon.request<Discarded>('discard', { handle: this.handle });
        this.dirty.clear();
        this.touch('clean');
        return answer.discarded;
    }

    /** What a save would do, deciding it exactly as the save would. */
    async preview(rebuild = false): Promise<Preview> {
        const answer = await this.daemon.request<Committed>('commit', {
            handle: this.handle,
            dry_run: true,
            rebuild,
        });
        return {
            method: answer.method ?? 'patch',
            planned: answer.planned ?? [],
            rejected: answer.rejected ?? [],
        };
    }

    /**
     * Commits every buffered edit at once.
     *
     * `undefined` when there was nothing to commit. A failure — a refusal, or a
     * cancel — leaves the edits buffered on both sides, so the same save can be
     * asked for again once whatever refused it has been dealt with.
     */
    async save(options: SaveOptions = {}): Promise<Saved | undefined> {
        if (this.saveState === 'saving') {
            throw new SessionBusy('this archive is already being saved');
        }
        if (this.dirty.size === 0) {
            return undefined;
        }
        const params = {
            handle: this.handle,
            rebuild: options.rebuild ?? false,
            force: options.force ?? false,
            progress: options.onProgress !== undefined,
        };
        const call = this.daemon.send<Committed>('commit', params, options.onProgress);
        this.saving = call.id;
        this.touch('saving');
        let answer: Committed;
        try {
            answer = await call.result;
        } catch (failure) {
            this.saving = undefined;
            this.touch(this.dirty.size === 0 ? 'clean' : 'dirty');
            throw failure;
        }
        this.saving = undefined;
        if (answer.unchanged) {
            this.dirty.clear();
            this.touch('clean');
            return undefined;
        }
        this.dirty.clear();
        this.entryCount = answer.entries ?? this.entryCount;
        this.byteLength = answer.len ?? this.byteLength;
        await this.refresh();
        this.touch('clean');
        return {
            method: answer.method ?? 'patch',
            committed: answer.committed,
            entries: this.entryCount,
            len: this.byteLength,
        };
    }

    /**
     * Asks the daemon to stop the save this session started.
     *
     * Named by the request that started it and by this handle: a cancel that
     * names nothing means "whatever is running", which is somebody else's work
     * as readily as this one's. A patch answers `cancelling: false` with the
     * reason, because a patch writes the bytes of one edit and has no part-way
     * to stop at. DR-008.
     */
    async cancelSave(): Promise<Cancelled> {
        const running = this.saving;
        if (running === undefined) {
            throw new SessionBusy('this archive is not being saved');
        }
        return this.daemon.cancel(running, this.handle);
    }

    /** Reads every entry back and reports what did not check out. */
    verify(onProgress?: (progress: Progress) => void): Promise<Verified> {
        return this.daemon.send<Verified>(
            'verify',
            { handle: this.handle, progress: onProgress !== undefined },
            onProgress,
        ).result;
    }

    /** The header, and what the entries add up to. */
    info(inside = ''): Promise<Summary> {
        return this.daemon.request<Summary>('info', {
            handle: this.handle,
            path: normalise(inside),
        });
    }

    /**
     * Writes every entry out to a tree on the daemon's filesystem.
     *
     * A cancelled extraction leaves the files it had already written, and no
     * manifest: a tree with no `.rpf-manifest.json` in it is the signature of
     * one that did not finish. DR-014.
     */
    extract(into: string, onProgress?: (progress: Progress) => void): Promise<Extracted> {
        return this.daemon.send<Extracted>(
            'extract',
            { handle: this.handle, into, progress: onProgress !== undefined },
            onProgress,
        ).result;
    }

    /** Re-reads the archive's shape. */
    async refresh(): Promise<void> {
        const rows = await this.daemon.request<Listed[]>('list', {
            handle: this.handle,
            recursive: true,
        });
        this.listing = Tree.of(rows);
        this.stamp = Date.now();
    }

    /** Releases the claim on the archive. Buffered edits go with it. */
    async close(): Promise<number> {
        const answer = await this.daemon.request<{ discarded: number }>('close', {
            handle: this.handle,
        });
        this.dirty.clear();
        this.touch('clean');
        return answer.discarded;
    }

    private touch(state: SaveState): void {
        this.stamp = Date.now();
        if (this.saveState === state) {
            return;
        }
        this.saveState = state;
        for (const listener of this.listeners) {
            listener(state);
        }
    }
}
