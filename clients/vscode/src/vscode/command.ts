/**
 * The `rpf` command outside the extension: on `PATH` in the editor's own
 * terminals, and installed for the whole machine only when asked.
 */

import { execFile } from 'node:child_process';

import * as vscode from 'vscode';

import {
    type Layout,
    addToProfile,
    currentHost,
    install,
    installable,
    layoutFor,
    onPath,
    profileFor,
    profileHolds,
    refresh,
    terminalPathFor,
    uninstall,
    userPathCommand,
} from '../core/command.js';
import type { Located } from '../core/locate.js';
import { located } from './binary.js';
import { note } from './messages.js';

/**
 * Prepends the bundled binary's folder to `PATH` in integrated terminals, again
 * whenever `rpf.binaryPath` changes, and keeps an installed copy current.
 */
export function pathInTerminals(context: vscode.ExtensionContext): vscode.Disposable[] {
    const apply = async (): Promise<Located> => {
        const found = await located(context);
        const terminals = context.environmentVariableCollection;
        terminals.description = 'Puts the rpf binary bundled with this extension on PATH.';
        const prefix = terminalPathFor(found, process.env.PATH);
        if (prefix === undefined) {
            terminals.delete('PATH');
        } else {
            terminals.prepend('PATH', prefix);
        }
        return found;
    };
    void apply()
        .then(async (found) => {
            const version = versionOf(context);
            if (found.found && found.source === 'bundled' && (await refresh(found.path, version, layout()))) {
                note(`replaced ${layout().binary} with ${found.version} from ${found.path}`);
            }
        })
        .catch((failure: unknown) => note(`putting rpf on PATH: ${String(failure)}`));
    return [
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration('rpf.binaryPath')) {
                void apply().catch((failure: unknown) => note(`putting rpf on PATH: ${String(failure)}`));
            }
        }),
    ];
}

/** Copies the located binary to the per-user location, and offers to put that on `PATH`. */
export async function installCommand(context: vscode.ExtensionContext): Promise<void> {
    const found = await located(context);
    if (!found.found) {
        note(found.instructions);
        void vscode.window.showErrorMessage('There is no rpf binary to install. The RPF log says where it looked.');
        return;
    }
    const source = installable(found);
    if (source === undefined) {
        void vscode.window.showInformationMessage(
            `${found.version} is already on your PATH at ${found.path}. Nothing was copied.`,
        );
        return;
    }
    const at = layout();
    const outcome = await attempt(`Installing rpf at ${at.binary}`, () =>
        install(source, versionOf(context), at),
    );
    if (outcome === undefined) {
        return;
    }
    if (outcome.done === 'refused') {
        void vscode.window.showErrorMessage(
            `${outcome.at} already holds ${outcome.holds}, which this extension did not install. It was left alone.`,
        );
        return;
    }
    const installed = `${found.version} is installed at ${outcome.at}.`;
    if (onPath(at.directory, process.env.PATH, process.platform, currentHost().home)) {
        void vscode.window.showInformationMessage(installed);
        return;
    }
    await offerPath(at, installed, found.source === 'bundled');
}

/** Removes the copy, only if it is still the one this extension installed. */
export async function uninstallCommand(): Promise<void> {
    const at = layout();
    const outcome = await attempt(`Removing ${at.binary}`, () => uninstall(at));
    if (outcome === undefined) {
        return;
    }
    if (outcome.done === 'refused') {
        void vscode.window.showErrorMessage(
            `${outcome.at} holds ${outcome.holds}, which this extension did not install. It was left alone.`,
        );
        return;
    }
    const removed =
        outcome.done === 'removed' ? `Removed ${outcome.at}.` : `There is nothing installed at ${outcome.at}.`;
    void vscode.window.showInformationMessage(`${removed} ${await leftOnPath(at)}`.trim());
}

/** Says the directory is not on `PATH`, and offers the one change that puts it there. */
async function offerPath(at: Layout, installed: string, bundled: boolean): Promise<void> {
    if (process.platform === 'win32') {
        const chosen = await vscode.window.showWarningMessage(
            `${installed} ${at.directory} is not on your PATH.`,
            'Add to user PATH',
        );
        if (chosen !== 'Add to user PATH') {
            return;
        }
        const run = userPathCommand(at.directory);
        const said = await attempt(
            `Adding ${at.directory} to your user PATH`,
            () =>
                new Promise<string>((settle, fail) => {
                    execFile(run.command, run.args, { timeout: 30_000 }, (failure, stdout, stderr) =>
                        failure ? fail(new Error(stderr.trim() || failure.message)) : settle(stdout.trim()),
                    );
                }),
        );
        if (said === undefined) {
            return;
        }
        const inside = bundled
            ? "VS Code's own terminals already have the bundled one."
            : "VS Code's own terminals see it once VS Code is restarted.";
        void vscode.window.showInformationMessage(
            `${said === 'present' ? `${at.directory} was already on your user PATH.` : `Added ${at.directory} to your user PATH.`} A terminal opened from now on outside VS Code finds rpf; ${inside}`,
        );
        return;
    }
    const profile = profileFor(currentHost());
    if (profile === undefined) {
        void vscode.window.showWarningMessage(
            `${installed} ${at.directory} is not on your PATH; add it in your shell's startup file.`,
        );
        return;
    }
    const chosen = await vscode.window.showWarningMessage(
        `${installed} ${at.directory} is not on your PATH. "Add to shell profile" appends one line to ${profile.file}.`,
        'Add to shell profile',
    );
    if (chosen !== 'Add to shell profile') {
        return;
    }
    const added = await attempt(`Appending to ${profile.file}`, () => addToProfile(profile));
    if (added === undefined) {
        return;
    }
    void vscode.window.showInformationMessage(
        added === 'present'
            ? `${profile.file} already has the line. Open a new terminal to use rpf.`
            : `Appended to ${profile.file}: ${profile.line}. Open a new terminal to use rpf.`,
    );
}

/** What uninstalling deliberately left: the folder may hold other commands. */
async function leftOnPath(at: Layout): Promise<string> {
    if (process.platform === 'win32') {
        return onPath(at.directory, process.env.PATH, 'win32')
            ? `${at.directory} is still on your user PATH; remove it in Environment Variables if you want.`
            : '';
    }
    const profile = profileFor(currentHost());
    if (profile === undefined || !(await profileHolds(profile).catch(() => false))) {
        return '';
    }
    return `${profile.file} still has the line it was given, since ${at.directory} may hold other commands: ${profile.line}`;
}

/**
 * Runs one filesystem or process step, and shows its own error — `EACCES` on a
 * read-only profile, `EPERM` renaming a running `rpf.exe` — with what it was doing.
 */
async function attempt<T>(doing: string, run: () => Promise<T>): Promise<T | undefined> {
    try {
        return await run();
    } catch (failure) {
        const said = failure instanceof Error ? failure.message : String(failure);
        note(`${doing}: ${said}`);
        void vscode.window.showErrorMessage(`${doing} failed: ${said}`);
        return undefined;
    }
}

function versionOf(context: vscode.ExtensionContext): string {
    return String((context.extension.packageJSON as { version?: unknown }).version ?? '');
}

function layout(): Layout {
    return layoutFor(currentHost());
}
