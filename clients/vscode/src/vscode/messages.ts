/**
 * Showing a failure as something to act on. R7.6.
 *
 * The classification is in `core/errors.ts`, which has no editor in it and is
 * tested against a live daemon. This file is the adapter: it puts the same
 * three lines into whichever of the editor's surfaces the failure reached.
 */

import * as vscode from 'vscode';

import { type Advice, DaemonError, EXIT, advise, render } from '../core/errors.js';

/** Where a failure is written out in full, whatever else the user is shown. */
let channel: vscode.OutputChannel | undefined;

/** The log, made once. */
export function log(): vscode.OutputChannel {
    channel ??= vscode.window.createOutputChannel('RPF');
    return channel;
}

/** Writes one line to the log, stamped. */
export function note(line: string): void {
    log().appendLine(`[${new Date().toISOString()}] ${line}`);
}

/**
 * Tells the user what went wrong and what to do about it.
 *
 * The headline is what fits in a notification; the reason and the instruction
 * go to the log, which is what "Show Details" opens. A stack trace is never
 * what is shown, which is R7.6 in one sentence.
 */
export async function report(failure: unknown, doing: string): Promise<Advice> {
    const advice = advise(failure);
    note(`${doing}: ${render(advice)}`);
    const chosen = await vscode.window.showErrorMessage(
        `${doing}: ${advice.headline}`,
        'Show Details',
    );
    if (chosen === 'Show Details') {
        log().show(true);
    }
    return advice;
}

/**
 * The same failure as one the editor's filesystem layer understands.
 *
 * The editor has its own small vocabulary for filesystem failures and shows it
 * in places a notification cannot reach — a failed save, a hover in the
 * explorer — so the categories that have a counterpart are given one, and the
 * message is the actionable text either way.
 */
export function asFileSystemError(failure: unknown, uri: vscode.Uri): vscode.FileSystemError {
    const advice = advise(failure);
    const message = `${advice.headline} ${advice.reason} ${advice.action}`;
    if (failure instanceof DaemonError) {
        switch (failure.code) {
            case EXIT.notFound:
                return vscode.FileSystemError.FileNotFound(message);
            case EXIT.refused:
                return vscode.FileSystemError.NoPermissions(message);
            case EXIT.io:
                return vscode.FileSystemError.Unavailable(message);
            default:
                break;
        }
    }
    note(`${uri.toString()}: ${render(advice)}`);
    return new vscode.FileSystemError(message);
}
