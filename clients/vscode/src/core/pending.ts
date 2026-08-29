/**
 * What a session has buffered, and what the archive holds once it is committed.
 *
 * **A listing is the archive on disk.** DR-028: `list` answers what is there
 * now, and `read` is the one method that prefers a buffered write. So a client
 * that forwarded `list` would show a created entry as absent, a deleted one as
 * present and a renamed one under its old name, until the save. This file is
 * the client's answer: the same change set the daemon holds, kept here as well,
 * and applied to the listing in **the daemon's own order**, so the two cannot
 * come to disagree about what the commit will produce.
 *
 * That order is DR-026's, stated by `rpf_core::edit::tree_of` and repeated in
 * {@link Pending.rowsOver}: **removals, then renames, then writes, then
 * directories.** It is part of the contract rather than an implementation
 * detail, because it is what lets one set rename over a path it also removes.
 *
 * **A change is keyed by the path the archive holds it at**, exactly as
 * `rpf_core::edit::Changes` is, and never by the path the change puts it at. A
 * buffered rename of `data` to `info` leaves the entry beneath it addressed as
 * `data/greeting.txt` for as long as it is buffered, and {@link Pending.address}
 * is what turns the path a user sees back into the one the daemon takes.
 *
 * Nothing here folds case. Two paths differing only in case are one name to the
 * container and two strings here, and the daemon refuses that collision when
 * the change is offered — so this file compares paths exactly and leaves the
 * answer to the side that knows the format. `docs/conventions.md` §1.
 */

import type { Listed } from './protocol.js';
import { normalise } from './uri.js';

/**
 * One buffered change, as `rpf_core::edit::Change` spells it.
 *
 * A rename carries only its destination, because the source is the key.
 */
export type Change =
    | { readonly kind: 'write'; readonly contents: Uint8Array; readonly create: boolean }
    | { readonly kind: 'remove'; readonly recursive: boolean }
    | { readonly kind: 'rename'; readonly to: string }
    | { readonly kind: 'mkdir' };

/**
 * What recording a change did to the set.
 *
 * `one` means the daemon's set becomes this one by buffering this single
 * change, which is what buffering it does anyway. `resync` means a key was
 * withdrawn or moved, and the daemon's buffer has no method for either — it
 * takes a change at a path and never takes one away — so the set has to be
 * discarded and sent again. DR-030.
 */
export type Recorded = 'one' | 'resync';

/** Whether `path` is `under`, or is `under` itself. Component-wise. */
export function atOrUnder(path: string, under: string): boolean {
    return path === under || path.startsWith(`${under}/`);
}

/** `path` with the `from` prefix replaced by `to`. */
export function moved(path: string, from: string, to: string): string {
    return path === from ? to : `${to}${path.slice(from.length)}`;
}

/** Whether a change puts something in the archive that is not there yet. */
function creates(change: Change): boolean {
    return change.kind === 'mkdir' || (change.kind === 'write' && change.create);
}

/** A set of buffered changes, at most one per path. */
export class Pending {
    private readonly changes = new Map<string, Change>();

    /** How many changes are buffered. */
    get size(): number {
        return this.changes.size;
    }

    /** Every path a change is recorded at, in order. */
    paths(): string[] {
        return [...this.changes.keys()].sort();
    }

    /** Every change, by its path, in the order a commit applies them. */
    ordered(): [string, Change][] {
        const order: Change['kind'][] = ['remove', 'rename', 'write', 'mkdir'];
        return order.flatMap((kind) =>
            this.paths()
                .map((path): [string, Change] => [path, this.changes.get(path) as Change])
                .filter(([, change]) => change.kind === kind),
        );
    }

    /** The change buffered at a path, if there is one. */
    at(path: string): Change | undefined {
        return this.changes.get(path);
    }

    /** Forgets everything. */
    clear(): void {
        this.changes.clear();
    }

    /**
     * The path the daemon knows a visible path by.
     *
     * A buffered rename moves what the user sees without moving what the
     * archive holds, so a path an editor hands back has to be turned into the
     * one `write` and `delete` take. A path under no buffered rename already is
     * that path.
     */
    address(visible: string): string {
        const there = this.changes.get(visible);
        if (there !== undefined && creates(there)) {
            return visible;
        }
        for (const [from, change] of this.changes) {
            if (change.kind === 'rename' && atOrUnder(visible, change.to)) {
                return moved(visible, change.to, from);
            }
        }
        return visible;
    }

    /**
     * Whether nothing on disk holds this path yet, so a write to it has to
     * carry `create` and a removal of it is a withdrawal rather than a change.
     */
    isCreated(held: string): boolean {
        const change = this.changes.get(held);
        return change !== undefined && creates(change);
    }

    /**
     * Why a rename cannot be buffered beside the renames already there, or
     * `undefined` when it can.
     *
     * `rpf_core::edit::tree_of` applies a set's renames in path order, so a
     * directory's rename runs before that of an entry inside it and leaves the
     * inner one addressing a path the tree no longer holds — the commit answers
     * `NotFound` for a set both halves of which were accepted when they were
     * offered. Refusing the second here is what keeps that out of the save.
     */
    blocksRename(held: string): string | undefined {
        for (const [key, change] of this.changes) {
            if (change.kind !== 'rename' || key === held) {
                continue;
            }
            if (atOrUnder(held, key)) {
                return `${key} is already being renamed, and this is inside it`;
            }
            if (atOrUnder(key, held)) {
                return `${key} inside it is already being renamed`;
            }
        }
        return undefined;
    }

    /**
     * Buffers a change at the path the archive holds it at, composing it with
     * whatever was buffered there already.
     *
     * @returns whether the daemon's set can follow with one request, or has to
     * be discarded and sent again. See {@link Recorded}.
     */
    record(held: string, change: Change): Recorded {
        if (change.kind === 'remove') {
            return this.recordRemoval(held, change);
        }
        if (change.kind === 'rename') {
            return this.recordRename(held, change.to);
        }
        this.changes.set(held, change);
        return 'one';
    }

    /**
     * The rows a listing would answer once this set is committed.
     *
     * DR-026's order, which is what makes this the same tree the rebuild
     * reaches: removals, then renames, then writes, then directories.
     */
    rowsOver(disk: readonly Listed[]): Listed[] {
        // Each row remembers the path the archive holds it at, because that is
        // what a buffered write is keyed by once a rename has moved the row.
        let rows = disk.map((row) => ({ row: { ...row }, held: normalise(row.path) }));

        for (const [path, change] of this.changes) {
            if (change.kind === 'remove') {
                rows = rows.filter((one) => !atOrUnder(one.row.path, path));
            }
        }
        for (const [path, change] of this.changes) {
            if (change.kind !== 'rename') {
                continue;
            }
            for (const one of rows) {
                if (atOrUnder(one.row.path, path)) {
                    one.row.path = moved(one.row.path, path, change.to);
                }
            }
        }
        for (const [path, change] of this.changes) {
            if (change.kind !== 'write') {
                continue;
            }
            const existing = rows.find((one) => one.held === path);
            if (existing) {
                existing.row.len = change.contents.length;
                continue;
            }
            rows.push({ row: { path, kind: 'binary', len: change.contents.length }, held: path });
        }
        for (const [path, change] of this.changes) {
            if (change.kind === 'mkdir') {
                rows.push({ row: { path, kind: 'directory', len: 0 }, held: path });
            }
        }
        return rows.map((one) => one.row);
    }

    /**
     * A removal takes every change beneath it with it, and a removal of
     * something only a buffered change put there withdraws that change instead
     * of recording anything.
     *
     * Withdrawing is the one thing the daemon's buffer cannot be told, which is
     * why this is where `resync` comes from.
     */
    private recordRemoval(held: string, change: Change): Recorded {
        const there = this.changes.get(held);
        let withdrew = false;
        for (const key of [...this.changes.keys()]) {
            if (key !== held && atOrUnder(key, held)) {
                this.changes.delete(key);
                withdrew = true;
            }
        }
        if (there !== undefined && creates(there)) {
            this.changes.delete(held);
            return 'resync';
        }
        this.changes.set(held, change);
        return withdrew ? 'resync' : 'one';
    }

    /**
     * A rename over a path a buffered change already created or moved is
     * composed rather than stacked: every change is resolved against the
     * archive on disk, so a set holding both would name a path no archive has.
     */
    private recordRename(held: string, to: string): Recorded {
        const there = this.changes.get(held);
        let rekeyed = false;
        for (const [key, change] of [...this.changes]) {
            if (atOrUnder(key, held) && creates(change)) {
                this.changes.delete(key);
                this.changes.set(moved(key, held, to), change);
                rekeyed = true;
            }
        }
        // Nothing on disk holds it, so moving the change that created it is the
        // whole of the rename and there is nothing left to record.
        if (there !== undefined && creates(there)) {
            return 'resync';
        }
        // A rename back to where the entry started is the withdrawal of the one
        // that moved it: recording `a → a` would be refused, since a rename's
        // destination may not be inside the entry being renamed.
        if (there !== undefined && to === held) {
            this.changes.delete(held);
            return 'resync';
        }
        this.changes.set(held, { kind: 'rename', to });
        return rekeyed ? 'resync' : 'one';
    }
}
