/**
 * The extension's editor surface.
 *
 * Everything decided here is decided in `src/core`, which imports no editor.
 * What is left is the part only a running editor exercises: commands, a status
 * bar, a progress dialog, and the workspace-folder call that mounts an archive.
 */

import * as vscode from 'vscode';

import { DaemonError, advise, render } from './core/errors.js';
import type { Progress } from './core/protocol.js';
import type { ArchiveSession, SaveOptions, Saved } from './core/session.js';
import { SCHEME, rootOf } from './core/uri.js';
import { Archives, type Mounted } from './vscode/archives.js';
import { AutoSave } from './vscode/autosave.js';
import { Decorations } from './vscode/decorations.js';
import { RpfFileSystem } from './vscode/filesystem.js';
import { serveMcp } from './vscode/mcp.js';
import { log, note, report } from './vscode/messages.js';

/** What the extension hands back, which only its own editor suite asks for. */
export interface Api {
    decorations: Decorations;
}

/** Starts the extension. */
export function activate(context: vscode.ExtensionContext): Api {
    const archives = new Archives(context);
    const files = new RpfFileSystem(archives);
    const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    status.command = 'rpf.saveArchive';
    // Before the listener below, so that an archive is out of the held set by
    // the time the status bar is asked what to show.
    const autosave = new AutoSave(archives, files);
    const decorations = new Decorations(archives);

    context.subscriptions.push(
        vscode.workspace.registerFileSystemProvider(SCHEME, files, { isCaseSensitive: true }),
        vscode.window.registerFileDecorationProvider(decorations),
        status,
        autosave,
        decorations,
        { dispose: () => void archives.dispose() },
        archives.onDidChange(() => showState(autosave, status)),
        autosave.onDidHold((held) => {
            showState(autosave, status);
            void vscode.window
                .showWarningMessage(
                    `${basename(held.path)}: ${held.edits} edit(s) could not be written for you. ${held.why}`,
                    'Rebuild Now',
                )
                .then((chosen) => {
                    if (chosen === 'Rebuild Now') {
                        void vscode.commands.executeCommand('rpf.saveArchive', held.path);
                    }
                });
        }),
        archives.onImported((event) => {
            if ('failure' in event) {
                void report(event.failure, `re-importing ${event.inside}`);
            }
        }),
        ...serveMcp(context),
    );

    register(context, 'rpf.mountArchive', (uri?: vscode.Uri) => mount(archives, files, uri));
    register(context, 'rpf.unmountArchive', () => unmount(archives));
    register(context, 'rpf.saveArchive', (path?: string) => save(archives, files, autosave, path));
    register(context, 'rpf.discardEdits', () => discard(archives, files));
    register(context, 'rpf.verifyArchive', () => verify(archives));
    register(context, 'rpf.handOff', (uri?: vscode.Uri) => handOff(archives, uri));
    register(context, 'rpf.endHandOff', () => endHandOff(archives));

    // A window reopened on a saved workspace already has the folders; the
    // archives behind them have to be opened again before anything can be read.
    void remount(archives);
    showState(autosave, status);
    return { decorations };
}

/** Stops it. The daemon goes with the subscriptions. */
export function deactivate(): void {
    // Nothing: `Archives.dispose` is a subscription.
}

/**
 * One command, with whatever it throws turned into something to act on.
 *
 * The report is not awaited: a notification with a button is on screen until
 * the user answers it, and the command would not finish until they had.
 */
function register(
    context: vscode.ExtensionContext,
    id: string,
    run: (...args: never[]) => Promise<void> | void,
): void {
    context.subscriptions.push(
        vscode.commands.registerCommand(id, async (...args: never[]) => {
            try {
                await run(...args);
            } catch (failure) {
                void report(failure, id);
            }
        }),
    );
}

/** Opens every `rpf:` folder the window already holds. */
async function remount(archives: Archives): Promise<void> {
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
        if (folder.uri.scheme !== SCHEME || folder.uri.query.length === 0) {
            continue;
        }
        try {
            await archives.mount(folder.uri.query);
        } catch (failure) {
            note(`${folder.uri.query}: ${render(advise(failure))}`);
        }
    }
}

/**
 * An archive as a folder in the explorer.
 *
 * The archive is the one the command was given — the explorer context menu
 * passes the file that was right-clicked. Only an invocation with nothing to go
 * on opens a dialog.
 */
async function mount(
    archives: Archives,
    files: RpfFileSystem,
    given?: vscode.Uri,
): Promise<void> {
    const chosen = given ?? (await ask());
    if (!chosen) {
        return;
    }
    if (chosen.scheme !== 'file') {
        void vscode.window.showErrorMessage(
            `${chosen.toString()} is not a file on this machine. An archive is opened by its own path.`,
        );
        return;
    }
    const mounted = await archives.mount(chosen.fsPath);
    const root = vscode.Uri.from(rootOf(mounted.session.path));
    const existing = (vscode.workspace.workspaceFolders ?? []).findIndex(
        (folder) => folder.uri.toString() === root.toString(),
    );
    if (existing >= 0) {
        files.changed(mounted.session.path);
        await vscode.commands.executeCommand('revealInExplorer', root);
        return;
    }
    // The `(rpf)` suffix is the resource label formatter's, contributed in
    // `package.json`, which puts it on breadcrumbs and tabs as well.
    const name = basename(mounted.session.path);
    const added = vscode.workspace.updateWorkspaceFolders(
        vscode.workspace.workspaceFolders?.length ?? 0,
        0,
        { uri: root, name },
    );
    if (!added) {
        void vscode.window.showErrorMessage(
            `${name} could not be added to the workspace. Opening the folder directly instead.`,
        );
        await vscode.commands.executeCommand('vscode.openFolder', root, { forceNewWindow: true });
    }
}

/** Which archive to mount, when the invocation did not name one. */
async function ask(): Promise<vscode.Uri | undefined> {
    const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Mount',
        filters: { 'RAGE archives': ['rpf'] },
    });
    return picked?.[0];
}

/** Closes an archive, which is what releases the daemon's claim on it. */
async function unmount(archives: Archives): Promise<void> {
    const mount = await choose(archives, 'Unmount which archive?');
    if (!mount) {
        return;
    }
    if (mount.session.state === 'dirty') {
        const chosen = await vscode.window.showWarningMessage(
            `${basename(mount.session.path)} has ${mount.session.dirtyPaths().length} unsaved edit(s). Unmounting discards them.`,
            { modal: true },
            'Discard and Unmount',
        );
        if (chosen !== 'Discard and Unmount') {
            return;
        }
    }
    const root = vscode.Uri.from(rootOf(mount.session.path)).toString();
    const at = (vscode.workspace.workspaceFolders ?? []).findIndex(
        (folder) => folder.uri.toString() === root,
    );
    await archives.unmount(mount.session.path);
    if (at >= 0) {
        vscode.workspace.updateWorkspaceFolders(at, 1);
    }
}

/**
 * The one act that writes the archive.
 *
 * With `path`, the archive it names and no other: a caller that has already
 * said which archive it means must not be answered with a picker.
 */
async function save(
    archives: Archives,
    files: RpfFileSystem,
    autosave: AutoSave,
    path?: string,
): Promise<void> {
    const mount =
        path === undefined
            ? await choose(archives, 'Save which archive?')
            : archives.all().find((open) => open.session.path === path);
    if (!mount) {
        return;
    }
    const { session } = mount;
    if (session.state === 'clean') {
        void vscode.window.showInformationMessage(
            `${basename(session.path)} has no buffered edits.`,
        );
        return;
    }
    // Editors hold their own dirty buffers; saving those is what puts the edits
    // in the session in the first place.
    await vscode.workspace.saveAll(false);

    const saved = await autosave.asked(session, () => commit(session, {}));
    files.changed(session.path);
    if (!saved) {
        return;
    }
    const how = saved.method === 'patch' ? 'patched in place' : 'rebuilt';
    void vscode.window.showInformationMessage(
        `${basename(session.path)}: ${saved.committed} edit(s) ${how}; ${saved.entries} entries, ${saved.len} bytes.`,
    );
}

/**
 * The save itself, with the install guard answered by whoever asked for it.
 *
 * The daemon refuses a write inside a game installation, and only a person can
 * say that they meant it; nothing else here retries a refusal.
 */
async function commit(
    session: ArchiveSession,
    options: SaveOptions,
): Promise<Saved | undefined> {
    try {
        return await vscode.window.withProgress(
            {
                location: vscode.ProgressLocation.Notification,
                title: `Saving ${basename(session.path)}`,
                cancellable: true,
            },
            async (progress, token) => {
                const saving = session.begin({
                    ...options,
                    onProgress: (step) => progress.report(reported(step)),
                });
                token.onCancellationRequested(() => {
                    void session.cancelSave(saving.ticket).then(
                        (answer) => {
                            if (!answer.cancelling) {
                                progress.report({
                                    message: answer.reason ?? 'this cannot be stopped',
                                });
                            }
                        },
                        // A save that finished between the click and this call
                        // is nothing to tell the user about.
                        (failure: unknown) => note(`cancelling ${session.path}: ${String(failure)}`),
                    );
                });
                return saving.result;
            },
        );
    } catch (failure) {
        if (options.force === true || !guarded(failure)) {
            throw failure;
        }
        const chosen = await vscode.window.showWarningMessage(
            `${basename(session.path)} is inside a game installation.`,
            { modal: true, detail: advise(failure).reason },
            'Write into the game installation anyway',
        );
        if (chosen === undefined) {
            return undefined;
        }
        return commit(session, { ...options, force: true });
    }
}

/** Whether the daemon refused this only because of where the archive sits. */
function guarded(failure: unknown): boolean {
    return (
        failure instanceof DaemonError &&
        (failure.failure === 'GameInstall' || failure.failure === 'UncertainInstall')
    );
}

/** Throws away every buffered edit. */
async function discard(archives: Archives, files: RpfFileSystem): Promise<void> {
    const mount = await choose(archives, 'Discard the edits to which archive?');
    if (!mount) {
        return;
    }
    const chosen = await vscode.window.showWarningMessage(
        `Discard ${mount.session.dirtyPaths().length} buffered edit(s) to ${basename(mount.session.path)}?`,
        { modal: true },
        'Discard',
    );
    if (chosen !== 'Discard') {
        return;
    }
    const dropped = await mount.session.discard();
    files.changed(mount.session.path);
    void vscode.window.showInformationMessage(`Discarded ${dropped} edit(s).`);
}

/** Reads every entry back and reports what did not check out. */
async function verify(archives: Archives): Promise<void> {
    const mount = await choose(archives, 'Verify which archive?');
    if (!mount) {
        return;
    }
    const verified = await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Verifying ${basename(mount.session.path)}`,
            cancellable: false,
        },
        async (progress) =>
            mount.session.verify((step) => progress.report(reported(step))),
    );
    if (verified.problems.length === 0) {
        void vscode.window.showInformationMessage(
            `${verified.entries_checked} entries verified, no problems.`,
        );
        return;
    }
    log().appendLine(`--- ${verified.path}: ${verified.problems.length} problem(s) ---`);
    for (const problem of verified.problems) {
        log().appendLine(`  ${problem.path}: ${problem.reason}`);
    }
    log().show(true);
    void vscode.window.showWarningMessage(
        `${verified.problems.length} of ${verified.entries_checked} entries did not read back.`,
    );
}

/** Puts an out-of-scope asset on disk and watches it. */
async function handOff(archives: Archives, uri?: vscode.Uri): Promise<void> {
    const chosen = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (!chosen || chosen.scheme !== SCHEME) {
        void vscode.window.showInformationMessage(
            'Select a file inside a mounted archive first.',
        );
        return;
    }
    const mount = archives.at(chosen.query);
    if (!mount) {
        void vscode.window.showInformationMessage(`${chosen.query} is not mounted.`);
        return;
    }
    const inside = chosen.path.replace(/^\/+/, '');
    const handed = await mount.handoff.begin(inside);
    const opened = await vscode.window.showInformationMessage(
        `${inside} is at ${handed.file}. It is being watched: whatever writes it there is buffered as an edit.`,
        'Reveal',
    );
    if (opened === 'Reveal') {
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(handed.file));
    }
}

/** Stops watching every handed-off file of one archive. */
async function endHandOff(archives: Archives): Promise<void> {
    const mount = await choose(archives, 'Stop watching files of which archive?');
    if (!mount) {
        return;
    }
    const outstanding = mount.handoff.outstanding().length;
    mount.handoff.dispose();
    void vscode.window.showInformationMessage(`Stopped watching ${outstanding} file(s).`);
}

/** One of the mounted archives, asked for when there is more than one. */
async function choose(archives: Archives, title: string): Promise<Mounted | undefined> {
    const open = archives.all();
    const only = open[0];
    if (only === undefined) {
        void vscode.window.showInformationMessage(
            'No archive is mounted. Run "RPF: Mount Archive as Folder".',
        );
        return undefined;
    }
    if (open.length === 1) {
        return only;
    }
    const picked = await vscode.window.showQuickPick(
        open.map((mount) => ({
            label: basename(mount.session.path),
            description: mount.session.path,
            detail:
                mount.session.state === 'clean'
                    ? 'no buffered edits'
                    : `${mount.session.dirtyPaths().length} buffered edit(s)`,
            mount,
        })),
        { title },
    );
    return picked?.mount;
}

/** What a progress notification says, as the editor shows one. */
function reported(step: Progress): { message: string; increment?: number } {
    const missed = step.skipped > 0 ? ` (+${step.skipped} not shown)` : '';
    return {
        message: `${step.done} of ${step.total}: ${step.path}${missed}`,
    };
}

/**
 * The archives an autosave held back, in the status bar.
 *
 * Only those: an edit that is about to be written for the user is not something
 * to keep an eye on, and a badge that is always there says nothing.
 */
function showState(autosave: AutoSave, status: vscode.StatusBarItem): void {
    const held = autosave.stuck();
    if (held.length === 0) {
        status.hide();
        return;
    }
    const edits = held.reduce((count, one) => count + one.edits, 0);
    status.text = `$(warning) rpf: ${edits} edit(s) need a rebuild`;
    status.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    status.tooltip = held.map((one) => `${one.path} — ${one.why}`).join('\n');
    status.show();
}

/** The last component of a path, whichever separator it uses. */
function basename(at: string): string {
    const cut = Math.max(at.lastIndexOf('/'), at.lastIndexOf('\\'));
    return cut < 0 ? at : at.slice(cut + 1);
}
