/**
 * Where this window looks for the `rpf` binary: one search, shared by the
 * daemon, the MCP server and the command on `PATH`.
 */

import * as vscode from 'vscode';

import { locate, type Located } from '../core/locate.js';

/** The binary, looked for with the setting, the extension and `PATH`. */
export function located(context: vscode.ExtensionContext): Promise<Located> {
    return locate({
        setting: vscode.workspace.getConfiguration('rpf').get<string>('binaryPath'),
        extensionRoot: context.extensionPath,
        pathVariable: process.env.PATH,
    });
}
