/**
 * One open archive, and the changes held against it.
 *
 * A change is buffered rather than saved, and the set — writes, deletes,
 * renames and directories alike — is committed by one explicit act, because the
 * daemon decides patch-or-rebuild for the whole set. A listing is the archive
 * on disk, so every question about its shape is answered from the listing with
 * the buffered set applied. A set holds one change per path and the daemon
 * refuses a second, so a gesture that supersedes one takes it back with
 * `forget` first. An archive is open in one session at a time, so a leaked
 * handle locks the daemon out of its own archive.
 */

import type { Daemon } from './daemon.js';
import { Refused } from './errors.js';
import { type Change, type Offer, Pending, type Plan, type Shown } from './pending.js';
import type {
    Cancelled,
    Committed,
    Discarded,
    Extracted,
    Forgotten,
    Listed,
    Opened,
    Progress,
    ReadEntry,
    Structural,
    Summary,
    Verified,
} from './protocol.js';
import { Tree, isDirectory } from './tree.js';
import { normalise } from './uri.js';

/** Where a session's buffered changes stand. */
export type SaveState = 'clean' | 'dirty' | 'saving';

/** What a save did. */
export interface Saved {
    /** How the archive was written. */
    method: 'patch' | 'rebuild';
    /** How many buffered changes went in. `0` is a save held back. */
    committed: number;
    /** The archive's entry count afterwards. */
    entries: number;
    /** The archive's length afterwards. */
    len: number;
    /** Why the set would not patch, when that is what held the save back. */
    why?: string;
}

/** What a save would do, without doing any of it. */
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
    /** Write nothing unless the whole set patches in place. */
    patchOnly?: boolean;
    /** Write into a detected game installation anyway. */
    force?: boolean;
    onProgress?: (progress: Progress) => void;
}

/** One save on the lane, and the ticket a cancel names it by. */
export interface Saving {
    ticket: number;
    result: Promise<Saved | undefined>;
}

/** What a session knows about a save it has not answered yet. */
interface Ticket {
    /** The commit request, once one has been sent. */
    request: number | undefined;
    /** Whether a cancel took the save before it had a request to name. */
    abandoned: boolean;
}

/** Raised when a session is asked to stop work it is not doing. */
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

/** How a rename was asked for. */
export interface RenameOptions {
    /**
     * Whether an entry the destination already holds is removed to make room.
     *
     * The target is removed **in the same change set**, where removals are
     * applied before renames for exactly that reason. It is not a delete and a
     * create: the entry keeps its storage class and its kind.
     */
    overwrite?: boolean;
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
    /** Every save asked for and not yet answered, by the ticket that names it. */
    private readonly saves = new Map<number, Ticket>();
    private tickets = 0;
    private stamp = Date.now();
    private readonly listeners = new Set<(state: SaveState) => void>();
    private entryCount: number;
    private byteLength: number;
    /**
     * The lane every mutation runs in, one at a time.
     *
     * A write issued while a commit is running reaches the daemon only after
     * that commit has cleared its set, which is what keeps the two sides
     * describing the same archive. `cancelSave` stays out of it, having a
     * running save to stop.
     */
    private lane: Promise<unknown> = Promise.resolve();

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
     * The path is on the daemon's own filesystem, which is the only thing a
     * path on this wire has ever meant.
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
     * claimed, and what a refusal of a second `open` will name.
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
     * about a creation or a removal until the commit.
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

    /** Each buffered change, at the path the tree shows it at. */
    dirtyChanges(): Shown[] {
        return this.pending.shown();
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
     *
     * **Asked for as `auto`, which is the XML view where the entry has one.**
     * `RBF` and `PSO` are tokenised binary nobody can type, so what is
     * presented is the document the daemon converts them to and {@link write}
     * hands the same document back. The client converts nothing and decides
     * nothing from a path.
     */
    async read(inside: string): Promise<Uint8Array> {
        const answer = await this.daemon.request<ReadEntry>('read', {
            handle: this.handle,
            path: this.pending.address(normalise(inside)),
            as: 'auto',
        });
        return Buffer.from(answer.bytes, 'base64');
    }

    /**
     * Buffers a write. Nothing on disk changes until {@link save}.
     *
     * The daemon resolves the path and checks the payload now rather than at
     * commit, so a refusal — a directory, or a payload that is not the `RSC7` a
     * resource entry takes — arrives while the user can still act on it.
     * Without `create` a path the archive does not hold is exit 3, which is
     * what guards against creating an entry a caller merely misspelled.
     *
     * A write over a path this set removes is the removal withdrawn and these
     * contents in its place, which is the one change the set holds there.
     *
     * **Offered as `auto`, which is what {@link read} answered**, so a document
     * is converted back to the entry's own encoding before it is buffered and
     * anything that is not a document is offered exactly as it is. One visible
     * consequence: the length this session projects for an edited metadata
     * entry is the document's, because that is what this client holds.
     */
    write(inside: string, bytes: Uint8Array, options: WriteOptions = {}): Promise<void> {
        const visible = normalise(inside);
        return this.carry(() => {
            const held = this.pending.address(visible);
            const there = this.pending.at(held);
            // A rename and a write are two changes at one path, and a set holds
            // at most one — so buffering this would silently drop the rename.
            if (there?.kind === 'rename') {
                throw new Refused(
                    'refused',
                    visible,
                    `${visible} has a rename buffered against it, and one change set holds one change per entry. Save the archive, then edit it.`,
                );
            }
            // A directory the archive holds is the daemon's own refusal and is
            // left to it; a directory only this session made is one it cannot see.
            if (there?.kind === 'mkdir') {
                throw new Refused(
                    'is-a-directory',
                    visible,
                    `${visible} is a directory this change set makes`,
                );
            }
            // A creation is applied after the renames, so it is addressed by the
            // path it will have; a replacement, by the one the archive holds it at.
            const known = this.onDisk.at(held) !== undefined;
            const path = known ? held : visible;
            const create = !known && options.create === true;
            // Only a file can be replaced this way: one set cannot hold both
            // the removal of a directory and a write at that path.
            const gone = this.committed.at(path);
            if (this.pending.at(path)?.kind === 'remove' && gone !== undefined && isDirectory(gone)) {
                throw new Refused(
                    'is-a-directory',
                    visible,
                    `${visible} is a directory this change set removes; a file cannot take its place in one set. Save the archive, then write it.`,
                );
            }
            return this.pending.plan(path, visible, { kind: 'write', contents: bytes, create });
        });
    }

    /**
     * Buffers a removal. Nothing on disk changes until {@link save}.
     *
     * A removal of something only a buffered change put there withdraws that
     * change instead, as does a directory removed over the changes inside it.
     */
    remove(inside: string, options: RemoveOptions = {}): Promise<void> {
        const visible = normalise(inside);
        return this.carry(() => {
            const node = this.listing.at(visible);
            if (!node) {
                throw new Refused('not-found', visible, `${visible} is not in the archive`);
            }
            const recursive = options.recursive === true;
            // Asked of the view as well as the archive: a directory the archive
            // holds empty may hold buffered creations the daemon cannot see.
            if (!recursive && isDirectory(node) && node.children.size > 0) {
                throw new Refused(
                    'refused',
                    visible,
                    `${visible} is a directory that is not empty; ask for it recursively`,
                );
            }
            const held = this.pending.address(visible);
            return this.pending.plan(held, visible, { kind: 'remove', recursive });
        });
    }

    /**
     * Buffers a rename. Nothing on disk changes until {@link save}.
     *
     * A destination the view already holds is refused unless `overwrite` says
     * to replace it, and then the target is **removed in the same change set**,
     * where removals are applied before renames. The entry keeps its storage
     * class and its kind, because it is still a rename.
     */
    rename(from: string, to: string, options: RenameOptions = {}): Promise<void> {
        const source = normalise(from);
        const target = normalise(to);
        if (source === target) {
            return Promise.resolve();
        }
        return this.carry(() => {
            if (!this.listing.at(source)) {
                throw new Refused('not-found', source, `${source} is not in the archive`);
            }
            const occupied = this.listing.at(target);
            if (occupied && options.overwrite !== true) {
                throw new Refused('exists', target, `${target} is already in the archive`);
            }
            const held = this.pending.address(source);
            const blocked = this.pending.blocksRename(held);
            if (blocked !== undefined) {
                throw new Refused(
                    'refused',
                    source,
                    `${blocked}. Save the archive, then rename this one.`,
                );
            }
            const plans: Plan[] = [];
            if (occupied) {
                // Taking a non-empty directory recursively is a deletion the
                // user did not ask for, so it is refused rather than assumed.
                if (isDirectory(occupied) && occupied.children.size > 0) {
                    throw new Refused(
                        'refused',
                        target,
                        `${target} is a directory that is not empty. Delete it first, then rename over it.`,
                    );
                }
                plans.push(
                    this.pending.plan(this.pending.address(target), target, {
                        kind: 'remove',
                        recursive: false,
                    }),
                );
            }
            plans.push(this.pending.plan(held, source, { kind: 'rename', to: target }));
            return Pending.merged(plans);
        });
    }

    /** Buffers a directory. Nothing on disk changes until {@link save}. */
    makeDirectory(inside: string): Promise<void> {
        const visible = normalise(inside);
        return this.carry(() => {
            if (this.listing.at(visible)) {
                throw new Refused('exists', visible, `${visible} is already in the archive`);
            }
            return this.pending.plan(visible, visible, { kind: 'mkdir' });
        });
    }

    /** Drops every buffered change, on both sides. */
    discard(): Promise<number> {
        return this.serial(() => this.drop());
    }

    /** What a save would do, deciding it exactly as the save would. */
    preview(rebuild = false): Promise<Preview> {
        return this.serial(() => this.plan(rebuild));
    }

    private async drop(): Promise<number> {
        const answer = await this.daemon.request<Discarded>('discard', { handle: this.handle });
        this.pending.clear();
        this.reshape();
        this.touch('clean');
        return answer.discarded;
    }

    private async plan(rebuild: boolean): Promise<Preview> {
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
     *
     * With `patchOnly`, a set the daemon would rebuild is left buffered and
     * answered with a {@link Saved} that committed nothing and says why.
     */
    save(options: SaveOptions = {}): Promise<Saved | undefined> {
        return this.begin(options).result;
    }

    /**
     * The same save, with the ticket {@link cancelSave} names it by.
     *
     * A cancel that named nothing would stop whichever save was running, which
     * is somebody else's as readily as the caller's own.
     */
    begin(options: SaveOptions = {}): Saving {
        this.tickets += 1;
        const named = this.tickets;
        const ticket: Ticket = { request: undefined, abandoned: false };
        this.saves.set(named, ticket);
        const result = this.serial(() => this.commit(ticket, options)).finally(() => {
            this.saves.delete(named);
        });
        return { ticket: named, result };
    }

    private async commit(ticket: Ticket, options: SaveOptions): Promise<Saved | undefined> {
        if (ticket.abandoned || this.pending.size === 0) {
            return undefined;
        }
        if (options.patchOnly === true) {
            // There is no request to name across the dry run, so a cancel
            // arriving here takes the save back instead.
            const planned = await this.plan(options.rebuild ?? false);
            if (ticket.abandoned) {
                return undefined;
            }
            if (planned.method !== 'patch') {
                this.touch('dirty');
                return {
                    method: planned.method,
                    committed: 0,
                    entries: this.entryCount,
                    len: this.byteLength,
                    why: whyRebuilt(planned),
                };
            }
        }
        const params = {
            handle: this.handle,
            rebuild: options.rebuild ?? false,
            force: options.force ?? false,
            progress: options.onProgress !== undefined,
        };
        const call = this.daemon.send<Committed>('commit', params, options.onProgress);
        ticket.request = call.id;
        this.touch('saving');
        let answer: Committed;
        try {
            answer = await call.result;
        } catch (failure) {
            ticket.request = undefined;
            this.touch(this.pending.size === 0 ? 'clean' : 'dirty');
            throw failure;
        }
        ticket.request = undefined;
        // A commit is only sent with a set to commit, so an unchanged answer is
        // the two sides disagreeing; clearing here would drop the edits unseen.
        if (answer.unchanged) {
            this.touch('dirty');
            throw new Error(
                `${this.path} still holds ${this.pending.size} buffered edit(s) the daemon has no record of. Its session did not survive the last save: unmount the archive and mount it again.`,
            );
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
     * Asks the daemon to stop the save a {@link begin} named, and no other.
     *
     * Named by the request and this handle: a cancel that names nothing means
     * "whatever is running", which is somebody else's work as readily. A patch
     * answers `cancelling: false`, having no part-way to stop at.
     *
     * A save that has not reached the daemon yet has no request to name, so it
     * is taken back here instead and gives up before it begins.
     */
    async cancelSave(ticket: number): Promise<Cancelled> {
        const named = this.saves.get(ticket);
        if (named === undefined) {
            throw new SessionBusy('that save has already finished');
        }
        if (named.request === undefined) {
            named.abandoned = true;
            return { cancelling: true, running: 'commit' };
        }
        return this.daemon.cancel(named.request, this.handle);
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
     * A cancelled extraction leaves the files it had already written and no
     * manifest: a tree with no `.rpf-manifest.json` in it did not finish.
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
    close(): Promise<number> {
        return this.serial(() => this.release());
    }

    private async release(): Promise<number> {
        const answer = await this.daemon.request<{ discarded: number }>('close', {
            handle: this.handle,
        });
        this.pending.clear();
        this.reshape();
        this.touch('clean');
        return answer.discarded;
    }

    /**
     * Decides a gesture's whole plan, asks the daemon for it, and records it
     * once the daemon has taken all of it.
     *
     * The plan is decided **in the lane**, against a listing and a set no
     * commit can clear underneath it; a plan decided at call time and queued
     * would name paths a rebuild had since moved.
     *
     * Withdrawals go first, because the daemon refuses a second change at a
     * path its set already holds — `Error::Claimed`, exit 6.
     *
     * A plan is all of it or none of it: a refusal part-way puts back what was
     * withdrawn, so a gesture the daemon declines costs the gesture and never
     * the buffer.
     */
    private carry(decide: () => Plan): Promise<void> {
        return this.serial(() => this.buffer(decide()));
    }

    private async buffer(plan: Plan): Promise<void> {
        const withdrawn: Offer[] = [];
        const offered: string[] = [];
        try {
            for (const path of plan.forget) {
                const change = this.pending.at(path);
                await this.daemon.request<Forgotten>('forget', { handle: this.handle, path });
                if (change !== undefined) {
                    withdrawn.push([path, change]);
                }
            }
            for (const [path, change] of plan.offer) {
                await this.offer(path, change);
                offered.push(path);
            }
        } catch (failure) {
            await this.putBack(withdrawn, offered);
            throw failure;
        }
        this.pending.apply(plan);
        this.reshape();
        this.touch(this.pending.size === 0 ? 'clean' : 'dirty');
    }

    /**
     * Undoes as much of a plan as the daemon took, so that the two sets agree
     * on the one this session still holds.
     *
     * The changes put back were in the daemon's set moments ago and are offered
     * again unchanged. If even that is refused the two sets are discarded
     * instead: a set the daemon half holds is worse than no set, because the
     * save would write it.
     */
    private async putBack(withdrawn: readonly Offer[], offered: readonly string[]): Promise<void> {
        try {
            for (const path of offered) {
                await this.daemon.request<Forgotten>('forget', { handle: this.handle, path });
            }
            for (const [path, change] of withdrawn) {
                await this.offer(path, change);
            }
        } catch {
            this.pending.clear();
            await this.daemon
                .request<Discarded>('discard', { handle: this.handle })
                .catch(() => undefined);
            this.reshape();
            this.touch('clean');
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
                    as: 'auto',
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

    private serial<T>(work: () => Promise<T>): Promise<T> {
        const next = this.lane.then(work, work);
        this.lane = next.catch(() => undefined);
        return next;
    }

    /** Rebuilds the view: the listing with every buffered change applied. */
    private reshape(): void {
        this.listing = this.pending.size === 0 ? this.onDisk : Tree.of(this.pending.rowsOver(this.rows));
    }

    private touch(state: SaveState): void {
        this.stamp = Date.now();
        this.saveState = state;
        for (const listener of this.listeners) {
            listener(state);
        }
    }
}

/** Why a set will not patch, in the terms the daemon decided it in. */
function whyRebuilt(planned: Preview): string {
    // A structural change is a rebuild whatever else is in the set, so it is
    // what the sentence names first.
    return planned.structural.length > 0
        ? `${planned.structural.length} change(s) alter what the archive holds`
        : `${planned.rejected.length} edit(s) do not fit where they are`;
}
