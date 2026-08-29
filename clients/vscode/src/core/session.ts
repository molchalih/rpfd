/**
 * One open archive, and the changes held against it. R7.3.
 *
 * **A write is not free.** Saving one entry may patch its payload in place or
 * may rebuild the whole archive, and the daemon decides which for the *set* of
 * buffered changes before it writes any of them — R4.14. So a change here is
 * buffered rather than saved, and the set is committed by one explicit act.
 * That is what makes a 145 MB archive editable in a loop: the alternative is
 * deciding the question once per keystroke-sized change.
 *
 * **The set is structural as well.** DR-026 gives the daemon `write { create }`,
 * `delete`, `rename` and `mkdir`, all buffered the same way. What it does not
 * give is a listing that reflects them: DR-028 says a listing is the archive on
 * disk, and `read` is the one method that prefers what was buffered. So this
 * class keeps the set itself, in {@link Pending}, and every question about the
 * archive's shape is answered from the listing **with the set applied** —
 * otherwise a created entry would be invisible until the save. DR-030.
 *
 * **One writer per archive.** DR-009: an archive is open in one session at a
 * time and the second `open` is refused, so this class is the unit a client
 * counts. Nothing here opens an archive twice, and `close` is what releases the
 * claim — a leaked handle locks the daemon out of its own archive for the rest
 * of its life.
 */

import type { Daemon } from './daemon.js';
import { Refused } from './errors.js';
import { type Change, Pending } from './pending.js';
import type {
    Cancelled,
    Committed,
    Discarded,
    Extracted,
    Listed,
    Opened,
    Progress,
    ReadEntry,
    Structural,
    Summary,
    Verified,
    Wrote,
} from './protocol.js';
import { Tree, isDirectory } from './tree.js';
import { normalise } from './uri.js';

/** Where a session's buffered changes stand. */
export type SaveState = 'clean' | 'dirty' | 'saving';

/** What a save did. */
export interface Saved {
    /** How the archive was written. */
    method: 'patch' | 'rebuild';
    /** How many buffered changes went in. */
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
    /** Which changes no patch could express, and what each of them does. */
    structural: Structural[];
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

/** How a write was asked for. */
export interface WriteOptions {
    /** Whether a path the archive does not hold is created rather than refused. */
    create?: boolean;
}

/** How a removal was asked for. */
export interface RemoveOptions {
    /** Whether a directory takes its children with it. */
    recursive?: boolean;
}

/** An archive held open by the daemon, with its buffered changes. */
export class ArchiveSession {
    private readonly daemon: Daemon;
    private readonly opened: Opened;
    /** The archive as the last listing described it, which is the archive on disk. */
    private rows: readonly Listed[];
    private onDisk: Tree;
    private listing: Tree;
    private readonly pending = new Pending();
    private saveState: SaveState = 'clean';
    private saving: number | undefined;
    private stamp = Date.now();
    private readonly listeners = new Set<(state: SaveState) => void>();
    private entryCount: number;
    private byteLength: number;

    private constructor(daemon: Daemon, opened: Opened, rows: readonly Listed[]) {
        this.daemon = daemon;
        this.opened = opened;
        this.rows = rows;
        this.onDisk = Tree.of(rows);
        this.listing = this.onDisk;
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
        return new ArchiveSession(daemon, opened, rows);
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

    /** Where the buffered changes stand. */
    get state(): SaveState {
        return this.saveState;
    }

    /**
     * The archive's shape as a save would leave it: the listing with every
     * buffered change applied.
     *
     * Not the listing itself, which is the archive on disk and says nothing
     * about a creation or a removal until the commit. DR-028, DR-030.
     */
    get tree(): Tree {
        return this.listing;
    }

    /** The archive's shape as it is on disk, which is what `list` answers. */
    get committed(): Tree {
        return this.onDisk;
    }

    /** Which paths have a buffered change against them. */
    dirtyPaths(): string[] {
        return this.pending.paths();
    }

    /** The length an entry will have once the changes are saved. */
    lengthOf(inside: string): number | undefined {
        return this.listing.at(normalise(inside))?.len;
    }

    /** When this session last changed, for a file's modification time. */
    get changedAt(): number {
        return this.stamp;
    }

    /** Told whenever the buffered changes change state. */
    onStateChange(listener: (state: SaveState) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    /**
     * One entry's bytes: the buffered write when there is one, and what is on
     * disk otherwise.
     */
    async read(inside: string): Promise<Uint8Array> {
        const answer = await this.daemon.request<ReadEntry>('read', {
            handle: this.handle,
            path: this.pending.address(normalise(inside)),
        });
        return Buffer.from(answer.bytes, 'base64');
    }

    /**
     * Buffers a write. Nothing on disk changes until {@link save}.
     *
     * The daemon resolves the path and checks the payload now rather than at
     * commit, so a refusal — a directory, or a payload that is not the `RSC7` a
     * resource entry takes — arrives while the user can still act on it.
     *
     * `create` is what DR-026 added: a path the archive does not hold is an
     * entry added, and therefore a rebuild. Without it such a path is exit 3,
     * because creating an entry a caller merely misspelled is the failure that
     * guards against.
     */
    async write(inside: string, bytes: Uint8Array, options: WriteOptions = {}): Promise<void> {
        const visible = normalise(inside);
        const held = this.pending.address(visible);
        // A rename and a write are two changes at one path, and a set holds at
        // most one — so buffering this would silently drop the rename.
        // `edit::Changes` is keyed by path and has no change that does both, so
        // there is no set that expresses it either. DR-030.
        if (this.pending.at(held)?.kind === 'rename') {
            throw new Refused(
                'refused',
                visible,
                `${visible} has a rename buffered against it, and one change set holds one change per entry. Save the archive, then edit it.`,
            );
        }
        // A creation is applied after the renames, so it is addressed by the
        // path it will have; a replacement is addressed by the one the archive
        // holds it at, and found there by index. `edit::tree_of`.
        const known = this.onDisk.at(held) !== undefined;
        const path = known ? held : visible;
        const create = !known && options.create === true;
        await this.daemon.request<Wrote>('write', {
            handle: this.handle,
            path,
            bytes: Buffer.from(bytes).toString('base64'),
            create,
        });
        await this.buffer(path, { kind: 'write', contents: bytes, create });
    }

    /**
     * Buffers a removal. Nothing on disk changes until {@link save}.
     *
     * A removal of something only a buffered change put there is that change
     * withdrawn, and the daemon has no method for withdrawing one — so the set
     * is discarded and sent again. DR-030.
     */
    async remove(inside: string, options: RemoveOptions = {}): Promise<void> {
        const visible = normalise(inside);
        const node = this.listing.at(visible);
        if (!node) {
            throw new Refused('not-found', visible, `${visible} is not in the archive`);
        }
        const recursive = options.recursive === true;
        // Asked of the view rather than only of the archive, because the daemon
        // cannot see it: a directory the archive holds empty may hold buffered
        // creations, and one the archive does not hold at all is entirely
        // buffered. The daemon asks the same of the archive, and both answers
        // stand.
        if (!recursive && isDirectory(node) && node.children.size > 0) {
            throw new Refused(
                'refused',
                visible,
                `${visible} is a directory that is not empty; ask for it recursively`,
            );
        }
        const held = this.pending.address(visible);
        if (!this.pending.isCreated(held)) {
            await this.daemon.request('delete', { handle: this.handle, path: held, recursive });
        }
        await this.buffer(held, { kind: 'remove', recursive });
    }

    /**
     * Buffers a rename. Nothing on disk changes until {@link save}.
     *
     * A destination the archive already holds is refused with no way through:
     * DR-026 has no `overwrite`, because removing the target in the same set
     * says the same thing out loud and shows up in the plan. What that record
     * does not say, and what is true, is that the wire cannot carry it — the
     * daemon resolves a rename against the archive **on disk**, where a target
     * a buffered removal is about to free is still occupied. DR-030.
     */
    async rename(from: string, to: string): Promise<void> {
        const source = normalise(from);
        const target = normalise(to);
        if (source === target) {
            return;
        }
        if (!this.listing.at(source)) {
            throw new Refused('not-found', source, `${source} is not in the archive`);
        }
        if (this.listing.at(target)) {
            throw new Refused('exists', target, `${target} is already in the archive`);
        }
        const held = this.pending.address(source);
        // Putting an entry back where it came from is the withdrawal of the
        // rename that moved it, so the archive on disk holding that path is the
        // reason it is allowed rather than a reason to refuse.
        if (this.committed.at(target) && held !== target) {
            throw new Refused(
                'exists',
                target,
                `${target} is still in the archive on disk, and a rename is resolved against that rather than against what is buffered. Save the archive, then rename.`,
            );
        }
        const blocked = this.pending.blocksRename(held);
        if (blocked !== undefined) {
            throw new Refused(
                'refused',
                source,
                `${blocked}. Save the archive, then rename this one.`,
            );
        }
        // Neither of these is a rename the daemon can be asked for: one moves a
        // change that put something there, and one takes a change away. Both
        // are the set being rewritten, which is what `resync` is for.
        const rewriting =
            this.pending.isCreated(held) ||
            (held === target && this.pending.at(held)?.kind === 'rename');
        if (!rewriting) {
            await this.daemon.request('rename', { handle: this.handle, from: held, to: target });
        }
        await this.buffer(held, { kind: 'rename', to: target });
    }

    /** Buffers a directory. Nothing on disk changes until {@link save}. */
    async makeDirectory(inside: string): Promise<void> {
        const visible = normalise(inside);
        if (this.listing.at(visible)) {
            throw new Refused('exists', visible, `${visible} is already in the archive`);
        }
        await this.daemon.request('mkdir', { handle: this.handle, path: visible });
        await this.buffer(visible, { kind: 'mkdir' });
    }

    /** Drops every buffered change, on both sides. */
    async discard(): Promise<number> {
        if (this.saveState === 'saving') {
            throw new SessionBusy('the archive is being saved; cancel that first');
        }
        const answer = await this.daemon.request<Discarded>('discard', { handle: this.handle });
        this.pending.clear();
        this.reshape();
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
            structural: answer.structural ?? [],
        };
    }

    /**
     * Commits every buffered change at once.
     *
     * `undefined` when there was nothing to commit. A failure — a refusal, or a
     * cancel — leaves the changes buffered on both sides, so the same save can
     * be asked for again once whatever refused it has been dealt with.
     */
    async save(options: SaveOptions = {}): Promise<Saved | undefined> {
        if (this.saveState === 'saving') {
            throw new SessionBusy('this archive is already being saved');
        }
        if (this.pending.size === 0) {
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
            this.touch(this.pending.size === 0 ? 'clean' : 'dirty');
            throw failure;
        }
        this.saving = undefined;
        if (answer.unchanged) {
            this.pending.clear();
            this.reshape();
            this.touch('clean');
            return undefined;
        }
        this.pending.clear();
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
        this.rows = await this.daemon.request<Listed[]>('list', {
            handle: this.handle,
            recursive: true,
        });
        this.onDisk = Tree.of(this.rows);
        this.reshape();
    }

    /** Releases the claim on the archive. Buffered changes go with it. */
    async close(): Promise<number> {
        const answer = await this.daemon.request<{ discarded: number }>('close', {
            handle: this.handle,
        });
        this.pending.clear();
        this.reshape();
        this.touch('clean');
        return answer.discarded;
    }

    /**
     * Records a change the daemon has already accepted, and brings the daemon's
     * own set back in line when composing it withdrew or moved a key.
     *
     * The daemon's buffer takes a change at a path and has no method for taking
     * one away, so the only way to withdraw one is to discard the set and send
     * what is left. DR-030 says what that costs and what would remove it.
     */
    private async buffer(held: string, change: Change): Promise<void> {
        if (this.pending.record(held, change) === 'resync') {
            await this.resync();
        }
        this.reshape();
        this.touch(this.pending.size === 0 ? 'clean' : 'dirty');
    }

    /** Discards the daemon's set and sends this one, in the commit's own order. */
    private async resync(): Promise<void> {
        await this.daemon.request<Discarded>('discard', { handle: this.handle });
        try {
            for (const [path, change] of this.pending.ordered()) {
                await this.offer(path, change);
            }
        } catch (failure) {
            // Both sides end empty rather than disagreeing: a set the daemon
            // half holds is worse than no set, because the save would write it.
            this.pending.clear();
            await this.daemon
                .request<Discarded>('discard', { handle: this.handle })
                .catch(() => undefined);
            throw failure;
        }
    }

    /** One buffered change, as the method that buffers it. */
    private offer(path: string, change: Change): Promise<unknown> {
        const handle = this.handle;
        switch (change.kind) {
            case 'write':
                return this.daemon.request('write', {
                    handle,
                    path,
                    bytes: Buffer.from(change.contents).toString('base64'),
                    create: change.create,
                });
            case 'remove':
                return this.daemon.request('delete', {
                    handle,
                    path,
                    recursive: change.recursive,
                });
            case 'rename':
                return this.daemon.request('rename', { handle, from: path, to: change.to });
            case 'mkdir':
                return this.daemon.request('mkdir', { handle, path });
        }
    }

    /** Rebuilds the view: the listing with every buffered change applied. */
    private reshape(): void {
        this.listing = this.pending.size === 0 ? this.onDisk : Tree.of(this.pending.rowsOver(this.rows));
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
