/**
 * What a session has buffered, and what the archive holds once it is committed.
 *
 * A listing is the archive on disk and `read` is the one method that prefers a
 * buffered write, so the set is applied to the listing in the daemon's own
 * order — removals, then renames, then writes, then directories — which is what
 * lets one set rename over a path it also removes. A change is keyed by the
 * path the archive holds it at, never the path the change puts it at. A set
 * holds one change per path; a second change of another kind is refused rather
 * than applied. Nothing here folds case.
 */

import { Refused } from './errors.js';
import type { Listed } from './protocol.js';
import { normalise } from './uri.js';

/**
 * One buffered change, as `rpf_core::edit::Change` spells it.
 *
 * A rename carries only its destination, because the source is the key. A write
 * carries its contents because a gesture can move the key it is buffered at,
 * and because a plan that failed part-way puts back what it withdrew.
 */
export type Change =
    | { readonly kind: 'write'; readonly contents: Uint8Array; readonly create: boolean }
    | { readonly kind: 'remove'; readonly recursive: boolean }
    | { readonly kind: 'rename'; readonly to: string }
    | { readonly kind: 'mkdir' };

/** One change, at the path the archive holds it at. */
export type Offer = readonly [path: string, change: Change];

/**
 * What the daemon's buffer has to be told for its set to become this one.
 *
 * A gesture is not always one change: deleting a file this session created
 * takes a change **out** of the set, and renaming a directory this session made
 * re-keys the changes inside it. `forget` is what expresses both.
 *
 * Withdrawals come first, because the daemon refuses a second change at a path
 * its set already holds.
 */
export interface Plan {
    /** Paths whose buffered change is taken back, before anything is offered. */
    readonly forget: readonly string[];
    /** What to offer afterwards, in the order a commit applies them. */
    readonly offer: readonly Offer[];
}

/** The order a commit applies a set's changes in. `edit::tree_of`. */
const ORDER: Change['kind'][] = ['remove', 'rename', 'write', 'mkdir'];

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

/** What a change already in a set is, for a refusal that has to name it. */
function does(change: Change): string {
    switch (change.kind) {
        case 'write':
            return 'a write';
        case 'remove':
            return 'a removal';
        case 'rename':
            return 'a rename';
        case 'mkdir':
            return 'a new directory';
    }
}

/** Offers in the order a commit applies them, so a set is assembled as it means. */
function inCommitOrder(offers: readonly Offer[]): Offer[] {
    return ORDER.flatMap((kind) => offers.filter(([, change]) => change.kind === kind));
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
     * Why a second change cannot be recorded at a path beside the one already
     * there, or `undefined` when it can.
     *
     * `rpf_core::edit::Changes::admits`, with its two exceptions: two
     * **writes** replace, and the same change offered again is not a second
     * change. Anything else is `Error::Claimed` on the wire, so a refusal here.
     */
    admits(path: string, change: Change): string | undefined {
        const held = this.changes.get(path);
        if (held === undefined) {
            return undefined;
        }
        if (held.kind === 'write' && change.kind === 'write') {
            return undefined;
        }
        if (same(held, change)) {
            return undefined;
        }
        return `${path} already has ${does(held)} in this change set, which holds one change per path`;
    }

    /**
     * Why a rename cannot be buffered beside the renames already there, or
     * `undefined` when it can.
     *
     * `rpf_core::edit::tree_of` applies a set's renames in path order, so a
     * directory's rename runs first and leaves an inner one addressing a path
     * the tree no longer holds. Refusing the second here keeps that `NotFound`
     * out of the save.
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
     * What the daemon has to be told for its set to hold this change beside the
     * ones already there.
     *
     * Composition rather than replacement: a gesture that withdraws a change
     * withdraws it on both sides. Nothing here changes this set — the daemon is
     * asked first, and {@link Pending.apply} is what records the answer.
     *
     * @param held the path the archive holds the entry at, which is the key.
     * @param visible the path the user sees it at, which is the key a change
     * this session created is buffered under.
     * @throws Refused when one set cannot hold both changes, naming the one in
     * the way, before the request rather than after.
     */
    plan(held: string, visible: string, change: Change): Plan {
        if (change.kind === 'remove') {
            return this.planRemoval(held, change);
        }
        if (change.kind === 'rename') {
            return this.planRename(held, visible, change.to);
        }
        // "Gone, and then these contents" is those contents, which is the one
        // change a set holds at that key. Only a write can say it.
        if (change.kind === 'write' && this.changes.get(held)?.kind === 'remove') {
            return { forget: [held], offer: [[held, change]] };
        }
        this.refuseUnlessAdmitted(held, change);
        return { forget: [], offer: [[held, change]] };
    }

    /** Records what the daemon has accepted. */
    apply(plan: Plan): void {
        for (const path of plan.forget) {
            this.changes.delete(path);
        }
        for (const [path, change] of plan.offer) {
            this.changes.set(path, change);
        }
    }

    /** Two plans as one, so a gesture that is two changes is carried out once. */
    static merged(plans: readonly Plan[]): Plan {
        return {
            forget: plans.flatMap((plan) => [...plan.forget]),
            offer: inCommitOrder(plans.flatMap((plan) => [...plan.offer])),
        };
    }

    /**
     * The rows a listing would answer once this set is committed.
     *
     * In the order that makes this the same tree the rebuild reaches: removals,
     * then renames, then writes, then directories.
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
     * Whatever was buffered at the path itself goes too: the entry is leaving,
     * so an edit or a rename of it is void and a set holding both is refused.
     */
    private planRemoval(held: string, change: Change): Plan {
        const there = this.changes.get(held);
        const beneath = [...this.changes.keys()].filter(
            (key) => key !== held && atOrUnder(key, held),
        );
        const forget = there === undefined ? beneath : [...beneath, held];
        if (there !== undefined && creates(there)) {
            return { forget, offer: [] };
        }
        return { forget, offer: [[held, change]] };
    }

    /**
     * A rename of something a buffered change put there moves that change to
     * the key it will be found under, and a rename back to where an entry
     * started withdraws the one that moved it.
     *
     * A change this session created is keyed by the path it is **visible** at,
     * so that is the prefix the move is computed from; everything else is keyed
     * by the path the archive holds it at.
     */
    private planRename(held: string, visible: string, to: string): Plan {
        const moving = [...this.changes].filter(
            ([key, change]) => creates(change) && atOrUnder(key, visible),
        );
        const forget = moving.map(([key]) => key);
        const offer: Offer[] = moving.map(([key, change]) => [moved(key, visible, to), change]);
        const there = this.changes.get(held);
        // Nothing on disk holds it, so moving the change that created it is the
        // whole of the rename and there is no rename to offer.
        if (there !== undefined && creates(there)) {
            return { forget, offer: inCommitOrder(offer) };
        }
        if (there !== undefined && there.kind !== 'rename') {
            throw new Refused(
                'refused',
                visible,
                `${held} already has ${does(there)} in this change set, which holds one change per path. Save the archive, then rename it.`,
            );
        }
        if (there !== undefined) {
            forget.push(held);
        }
        // A rename back to where the entry started withdraws the one that moved
        // it: recording `a → a` would be refused.
        if (to !== held) {
            offer.push([held, { kind: 'rename', to }]);
        }
        return { forget, offer: inCommitOrder(offer) };
    }

    /** Refuses a change the set cannot hold beside the one already at its path. */
    private refuseUnlessAdmitted(path: string, change: Change): void {
        const claimed = this.admits(path, change);
        if (claimed !== undefined) {
            throw new Refused('refused', path, `${claimed}. Save the archive, then make this change.`);
        }
    }
}

/** Whether two changes are the same change, which is not a second one. */
function same(held: Change, change: Change): boolean {
    switch (held.kind) {
        case 'remove':
            return change.kind === 'remove' && change.recursive === held.recursive;
        case 'rename':
            return change.kind === 'rename' && change.to === held.to;
        case 'mkdir':
            return change.kind === 'mkdir';
        case 'write':
            return false;
    }
}
