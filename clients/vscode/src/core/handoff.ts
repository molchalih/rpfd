/**
 * Handing an entry to another tool, and taking it back.
 *
 * A passthrough entry's bytes are put on disk, opened in whatever tool does
 * understand them, and taken back when that tool writes them.
 *
 * The re-imported bytes are **buffered like any other edit**, not written
 * through: the archive is written by one explicit act, and a file watcher
 * firing is not one.
 *
 * The scratch file's name is this client's own invention and not the entry's,
 * so no rule about host names is written down twice.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import { type FSWatcher, type StatWatcher, unwatchFile, watch, watchFile } from 'node:fs';
import path from 'node:path';

import type { ArchiveSession } from './session.js';
import { normalise, split, tokenFor } from './uri.js';

/** Entry extensions this tool does not claim to understand. */
export const PASSTHROUGH = [
    '.ytd',
    '.ydr',
    '.ydd',
    '.yft',
    '.ycd',
    '.ynv',
    '.awc',
    '.ypt',
    '.yed',
    '.dds',
] as const;

/** How long a write is left to settle before the file is read back. */
const SETTLE_MS = 150;

/**
 * How often the handed-off file is stat-ed, beside the directory watch.
 *
 * Not a preference: on macOS every `fs.watch` in a process shares one FSEvents
 * stream, arming another tears that stream down and builds it again, and a
 * write during the rebuild is reported to nobody. The stat is what makes the
 * watch an optimisation rather than the mechanism.
 */
const POLL_MS = 500;

/** One entry that is out with another tool. */
export interface Handed {
    /** The path inside the archive. */
    inside: string;
    /** The file the other tool is editing. */
    file: string;
}

/** What happened when a handed-off file changed. */
export type Imported =
    | { inside: string; file: string; len: number }
    | { inside: string; file: string; failure: unknown };

/** How to hand off. */
export interface HandOffOptions {
    /** Where scratch files are written. */
    directory: string;
    /** Which extensions are out of scope. Lower case, with the dot. */
    extensions?: readonly string[];
}

/** Whether an entry is one this tool hands over rather than edits. */
export function isPassthrough(
    inside: string,
    extensions: readonly string[] = PASSTHROUGH as readonly string[],
): boolean {
    const { name } = split(inside);
    const dot = name.lastIndexOf('.');
    if (dot <= 0) {
        return false;
    }
    return extensions.includes(name.slice(dot).toLowerCase());
}

/**
 * The scratch file one entry is handed off as.
 *
 * The digest is what makes two entries with the same basename two files; the
 * trailing name is only so the other tool sees an extension it recognises.
 */
export function scratchFor(directory: string, archive: string, inside: string): string {
    const path_ = normalise(inside);
    const digest = createHash('sha256').update(path_, 'utf8').digest('hex').slice(0, 12);
    const { name } = split(path_);
    const plain = name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/[. ]+$/, '');
    return path.join(directory, tokenFor(archive), `${digest}-${plain || 'entry'}`);
}

/** Entries out with other tools, and the watchers that bring them back. */
export class HandOff {
    private readonly session: ArchiveSession;
    private readonly options: HandOffOptions;
    private readonly out = new Map<string, Handed>();
    private readonly known = new Map<string, string>();
    private readonly watchers = new Map<string, FSWatcher>();
    private readonly polls = new Map<string, StatWatcher>();
    private readonly timers = new Map<string, NodeJS.Timeout>();
    private readonly listeners = new Set<(event: Imported) => void>();

    constructor(session: ArchiveSession, options: HandOffOptions) {
        this.session = session;
        this.options = options;
    }

    /** Whether an entry is one this tool hands over. */
    handsOver(inside: string): boolean {
        return isPassthrough(inside, this.options.extensions ?? PASSTHROUGH);
    }

    /** What is currently out with another tool. */
    outstanding(): Handed[] {
        return [...this.out.values()];
    }

    /** Told whenever a handed-off file has been read back into the buffer. */
    onImported(listener: (event: Imported) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    /**
     * Writes one entry out and starts watching it.
     *
     * A resource entry lands with its `RSC7` header, which is what the other
     * tool expects and what the daemon will accept back.
     */
    async begin(inside: string): Promise<Handed> {
        const path_ = normalise(inside);
        const existing = this.out.get(path_);
        if (existing) {
            return existing;
        }
        const file = scratchFor(this.options.directory, this.session.path, path_);
        const bytes = await this.session.read(path_);
        await fs.mkdir(path.dirname(file), { recursive: true });
        await fs.writeFile(file, bytes);
        this.known.set(path_, digestOf(bytes));
        const handed: Handed = { inside: path_, file };
        this.out.set(path_, handed);
        this.observe(handed);
        return handed;
    }

    /**
     * Reads a handed-off file back and buffers it as an edit.
     *
     * Bytes identical to what went out are not written: an editor that touches
     * a file without changing it must not make the archive dirty.
     */
    async reimport(inside: string): Promise<Imported | undefined> {
        const handed = this.out.get(normalise(inside));
        if (!handed) {
            return undefined;
        }
        let event: Imported;
        try {
            const bytes = await fs.readFile(handed.file);
            const digest = digestOf(bytes);
            if (this.known.get(handed.inside) === digest) {
                return undefined;
            }
            await this.session.write(handed.inside, bytes);
            this.known.set(handed.inside, digest);
            event = { inside: handed.inside, file: handed.file, len: bytes.length };
        } catch (failure) {
            event = { inside: handed.inside, file: handed.file, failure };
        }
        for (const listener of this.listeners) {
            listener(event);
        }
        return event;
    }

    /** Stops watching one entry. The file on disk is left where it is. */
    end(inside: string): void {
        const path_ = normalise(inside);
        this.watchers.get(path_)?.close();
        this.watchers.delete(path_);
        const handed = this.out.get(path_);
        if (handed && this.polls.delete(path_)) {
            unwatchFile(handed.file);
        }
        const timer = this.timers.get(path_);
        if (timer) {
            clearTimeout(timer);
        }
        this.timers.delete(path_);
        this.out.delete(path_);
        this.known.delete(path_);
    }

    /** Stops watching everything. */
    dispose(): void {
        for (const inside of [...this.out.keys()]) {
            this.end(inside);
        }
        this.listeners.clear();
    }

    /**
     * Watches the *directory* rather than the file, and stats the file beside
     * it.
     *
     * The directory because a replace-by-rename drops a watch held on the file
     * itself; the stat because a watch can miss the event outright — see
     * {@link POLL_MS}. Both feed one settle timer, and noticing twice costs a
     * digest.
     */
    private observe(handed: Handed): void {
        const directory = path.dirname(handed.file);
        const name = path.basename(handed.file);
        const watcher = watch(directory, (_event, changed) => {
            if (changed !== null && changed !== name) {
                return;
            }
            this.settle(handed);
        });
        watcher.on('error', () => this.end(handed.inside));
        this.watchers.set(handed.inside, watcher);

        const poll = watchFile(handed.file, { interval: POLL_MS }, (current) => {
            // A file that is not there has nothing to bring back, and reading
            // it would report a failure the user did not cause.
            if (current.mtimeMs !== 0) {
                this.settle(handed);
            }
        });
        poll.unref();
        this.polls.set(handed.inside, poll);
    }

    /** Reads the file back once whatever is writing it has stopped. */
    private settle(handed: Handed): void {
        const running = this.timers.get(handed.inside);
        if (running) {
            clearTimeout(running);
        }
        this.timers.set(
            handed.inside,
            setTimeout(() => {
                this.timers.delete(handed.inside);
                void this.reimport(handed.inside);
            }, SETTLE_MS),
        );
    }
}

/** What the bytes are, for telling a real change from a touch. */
function digestOf(bytes: Uint8Array): string {
    return createHash('sha256').update(bytes).digest('hex');
}
