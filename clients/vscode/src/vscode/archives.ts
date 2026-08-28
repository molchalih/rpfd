/**
 * The archives this window has open, and the one daemon behind them.
 *
 * One daemon per window rather than one per archive: DR-002's whole argument is
 * that the table of contents is parsed once and kept warm, and a process per
 * archive would pay the process cost instead.
 *
 * One session per archive, and the registry is what makes that true on this
 * side. DR-009 refuses the second `open` anyway, but a client that had to
 * discover its own duplicate mount from a refusal would be finding out at the
 * wrong end.
 */

import * as vscode from 'vscode';

import { Daemon } from '../core/daemon.js';
import { TransportError } from '../core/errors.js';
import { HandOff, type Imported, PASSTHROUGH } from '../core/handoff.js';
import { locate } from '../core/locate.js';
import { ArchiveSession } from '../core/session.js';
import { note } from './messages.js';

/** One mounted archive. */
export interface Mounted {
    session: ArchiveSession;
    handoff: HandOff;
}

/** Everything this window holds open. */
export class Archives {
    private readonly context: vscode.ExtensionContext;
    private readonly mounted = new Map<string, Mounted>();
    private readonly changed = new vscode.EventEmitter<void>();
    private daemon: Daemon | undefined;
    private starting: Promise<Daemon> | undefined;
    private closing = false;

    private readonly imported = new vscode.EventEmitter<Imported>();

    /** Fires whenever an archive is mounted, unmounted, or changes state. */
    readonly onDidChange = this.changed.event;

    /**
     * Fires when a handed-off file has been read back.
     *
     * Here rather than on each {@link HandOff} so that a listener is attached
     * once per mount: a command that subscribed each time it ran would report
     * one re-import as many times as it had been invoked.
     */
    readonly onImported = this.imported.event;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }

    /** Every archive this window has open, by its resolved path. */
    all(): Mounted[] {
        return [...this.mounted.values()];
    }

    /** The session for an archive, if it is mounted. */
    at(archive: string): Mounted | undefined {
        return this.mounted.get(archive);
    }

    /**
     * Mounts an archive, or gives back the session already holding it.
     *
     * The daemon reports the path it resolved, and that is what the registry is
     * keyed on: two spellings of one archive are one mount, which is the same
     * rule DR-009 applies one layer down.
     */
    async mount(archive: string): Promise<Mounted> {
        const existing = this.mounted.get(archive);
        if (existing) {
            return existing;
        }
        const daemon = await this.running();
        const session = await ArchiveSession.open(daemon, archive);
        const already = this.mounted.get(session.path);
        if (already) {
            await session.close();
            return already;
        }
        const handoff = new HandOff(session, {
            directory: this.handOffDirectory(),
            extensions: this.handOffExtensions(),
        });
        const mount: Mounted = { session, handoff };
        this.mounted.set(session.path, mount);
        session.onStateChange(() => this.changed.fire());
        handoff.onImported((event) => {
            this.imported.fire(event);
            this.changed.fire();
        });
        this.changed.fire();
        return mount;
    }

    /** Closes an archive, releasing the daemon's claim on it. */
    async unmount(archive: string): Promise<void> {
        const mount = this.mounted.get(archive);
        if (!mount) {
            return;
        }
        this.mounted.delete(archive);
        mount.handoff.dispose();
        await mount.session.close();
        this.changed.fire();
    }

    /** Closes everything and stops the daemon. */
    async dispose(): Promise<void> {
        this.closing = true;
        for (const archive of [...this.mounted.keys()]) {
            await this.unmount(archive).catch(() => undefined);
        }
        await this.daemon?.dispose();
        this.daemon = undefined;
        this.changed.dispose();
        this.imported.dispose();
    }

    /** The daemon, started if it is not running yet. */
    private running(): Promise<Daemon> {
        if (this.daemon?.running) {
            return Promise.resolve(this.daemon);
        }
        this.starting ??= this.startDaemon().finally(() => {
            this.starting = undefined;
        });
        return this.starting;
    }

    private async startDaemon(): Promise<Daemon> {
        const settings = vscode.workspace.getConfiguration('rpf');
        const found = await locate({
            setting: settings.get<string>('binaryPath'),
            extensionRoot: this.context.extensionPath,
            pathVariable: process.env.PATH,
        });
        if (!found.found) {
            note(found.instructions);
            throw new TransportError(found.instructions);
        }
        note(`using ${found.path} (${found.version}, found as ${found.source})`);
        const daemon = Daemon.start({
            binary: found.path,
            onLog: (line) => {
                if (line.length < 4096) {
                    note(`< ${line}`);
                }
            },
        });
        this.daemon = daemon;
        void daemon.exited.then(() => this.recover(daemon));
        return daemon;
    }

    /**
     * What to do when the daemon has gone. DR-002 assigns this to the client.
     *
     * Every handle it issued went with it, and so did every buffered edit —
     * they were held in the daemon's session, which is the point of DR-002's
     * warm state. So the archives are opened again against a new daemon and the
     * user is told what was lost, rather than being left with a folder whose
     * every read fails.
     */
    private async recover(gone: Daemon): Promise<void> {
        if (this.closing || this.daemon !== gone) {
            return;
        }
        this.daemon = undefined;
        const archives = [...this.mounted.keys()];
        const lost = this.all().reduce(
            (count, mount) => count + mount.session.dirtyPaths().length,
            0,
        );
        for (const mount of this.mounted.values()) {
            mount.handoff.dispose();
        }
        this.mounted.clear();
        this.changed.fire();
        if (archives.length === 0) {
            return;
        }
        note(`the daemon went; re-opening ${archives.length} archive(s)`);
        for (const archive of archives) {
            try {
                await this.mount(archive);
            } catch (failure) {
                note(`${archive} could not be re-opened: ${String(failure)}`);
            }
        }
        const edits = lost === 0 ? '' : ` ${lost} buffered edit(s) were lost.`;
        void vscode.window.showWarningMessage(
            `The rpf daemon stopped and was restarted.${edits}`,
        );
    }

    private handOffDirectory(): string {
        const configured = vscode.workspace.getConfiguration('rpf').get<string>('handOff.directory');
        if (configured && configured.trim().length > 0) {
            return configured.trim();
        }
        return this.context.globalStorageUri.fsPath;
    }

    private handOffExtensions(): readonly string[] {
        const configured = vscode.workspace
            .getConfiguration('rpf')
            .get<string[]>('handOff.extensions');
        return configured && configured.length > 0 ? configured : PASSTHROUGH;
    }
}
