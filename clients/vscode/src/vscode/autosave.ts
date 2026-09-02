/**
 * Writing the archive for the user, whenever the daemon can patch it.
 *
 * A buffered edit arms a timer; the timer commits, and the daemon decides. A
 * set it would rebuild is held instead: rebuilding an archive behind somebody's
 * back is not a save, it is a rewrite. A held archive is never armed again
 * until it is clean, which is what stops a retry loop and a storm of the same
 * notification.
 */

import * as vscode from 'vscode';

import { advise } from '../core/errors.js';
import type { ArchiveSession } from '../core/session.js';
import type { Archives, Mounted } from './archives.js';
import type { RpfFileSystem } from './filesystem.js';
import { report } from './messages.js';

/** How long an archive gathers edits before the timer writes it. */
const SETTLE_MS = 250;

/** An archive whose edits are waiting for an explicit rebuild. */
export interface Held {
    /** The archive, as the daemon resolved it. */
    path: string;
    /** Why its edits were not written. */
    why: string;
    /** How many of them are waiting. */
    edits: number;
}

/** The timer that saves each mounted archive. */
export class AutoSave {
    private readonly archives: Archives;
    private readonly files: RpfFileSystem;
    private readonly timers = new Map<string, NodeJS.Timeout>();
    private readonly holding = new Map<string, Held>();
    private readonly writing = new Set<string>();
    private readonly watching: vscode.Disposable;
    private readonly withheld = new vscode.EventEmitter<Held>();

    /** Fires when an archive's edits stop being written for it. */
    readonly onDidHold = this.withheld.event;

    constructor(archives: Archives, files: RpfFileSystem) {
        this.archives = archives;
        this.files = files;
        this.watching = archives.onDidChange(() => this.follow());
    }

    /**
     * Runs a save the user asked for, with the timer kept off that archive
     * until something changes again: a refusal the user is already being told
     * about must not be repeated behind the message.
     */
    async asked<T>(session: ArchiveSession, work: () => Promise<T>): Promise<T> {
        this.writing.add(session.path);
        try {
            return await work();
        } finally {
            this.writing.delete(session.path);
        }
    }

    /** Every archive waiting for a rebuild the user has to ask for. */
    stuck(): Held[] {
        return [...this.holding.values()];
    }

    dispose(): void {
        this.watching.dispose();
        for (const timer of this.timers.values()) {
            clearTimeout(timer);
        }
        this.timers.clear();
        this.holding.clear();
        this.writing.clear();
        this.withheld.dispose();
    }

    private follow(): void {
        for (const mount of this.archives.all()) {
            const at = mount.session.path;
            if (mount.session.state === 'clean') {
                this.stop(at);
                this.holding.delete(at);
            } else if (mount.session.state === 'dirty') {
                const held = this.holding.get(at);
                if (held !== undefined) {
                    // Every edit since the hold is buffered and waiting too, and
                    // the count is the only signal the user gets.
                    held.edits = mount.session.dirtyPaths().length;
                } else if (!this.writing.has(at)) {
                    // A running save reports itself dirty before it answers, and
                    // a timer armed on that would commit the same set twice.
                    this.arm(mount);
                }
            }
        }
        // An unmount, a dispose and a daemon that died all leave a timer, a
        // hold and a badge for an archive nothing holds any more.
        for (const at of [...this.timers.keys(), ...this.holding.keys(), ...this.writing]) {
            if (this.archives.at(at) === undefined) {
                this.stop(at);
                this.holding.delete(at);
                this.writing.delete(at);
            }
        }
    }

    private arm(mount: Mounted): void {
        const at = mount.session.path;
        // Never restarted: edits arriving faster than the settle time in two
        // archives at once would leave neither of them ever written.
        if (this.timers.has(at)) {
            return;
        }
        this.timers.set(
            at,
            setTimeout(() => {
                this.timers.delete(at);
                void this.commit(mount.session);
            }, SETTLE_MS),
        );
    }

    private stop(at: string): void {
        const timer = this.timers.get(at);
        if (timer !== undefined) {
            clearTimeout(timer);
            this.timers.delete(at);
        }
    }

    private async commit(session: ArchiveSession): Promise<void> {
        // Recorded before the save is asked for, because the save reports the
        // state change that brings `follow` back round synchronously.
        this.writing.add(session.path);
        let saved;
        try {
            saved = await session.save({ patchOnly: true });
        } catch (failure) {
            this.hold(session, advise(failure).reason);
            void report(failure, `saving ${session.path}`);
            return;
        } finally {
            this.writing.delete(session.path);
        }
        this.files.changed(session.path);
        if (saved?.committed === 0) {
            this.hold(session, `a save would rebuild the archive: ${saved.why}.`);
        }
    }

    private hold(session: ArchiveSession, why: string): void {
        const held: Held = { path: session.path, why, edits: session.dirtyPaths().length };
        this.holding.set(held.path, held);
        this.withheld.fire(held);
    }
}
