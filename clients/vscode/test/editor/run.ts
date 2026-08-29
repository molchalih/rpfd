/**
 * Launching a real VS Code with this extension in it. R7.1, R7.2, R7.3.
 *
 * `npm test` drives `src/core` against a live daemon and never loads an editor.
 * Everything in `src/vscode` and `src/extension.ts` is the editor's own API,
 * and the only evidence that it works is a running editor: a downloaded VS
 * Code, launched with this directory as an extension under development and
 * {@link suite} as its tests. `npm run test:editor` is that run.
 *
 * The binary is given to the extension the way a user gives it one — the
 * `rpf.binaryPath` setting, written into the throwaway user directory this
 * launch gets — so the launch exercises `core/locate.ts` in place rather than
 * arranging around it.
 *
 * The window opens on a **workspace file** holding one empty folder, not on a
 * folder. `updateWorkspaceFolders` restarts every extension in the window when
 * it changes the *first* folder, so a mount into a single-folder window would
 * tear down the host mid-test. A second folder added to a workspace does not.
 */

import fs from 'node:fs';
import path from 'node:path';

import { downloadAndUnzipVSCode, runTests } from '@vscode/test-electron';

import { RPF, SKIP, scratch } from '../support.js';

async function main(): Promise<void> {
    if (!RPF) {
        console.log(`# skipped: the editor tests need a daemon — ${SKIP}`);
        return;
    }
    const root = path.resolve(__dirname, '..', '..', '..');
    const stage = scratch('editor');
    const userData = path.join(stage, 'user-data');
    const folder = path.join(stage, 'workspace');
    fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
    fs.mkdirSync(folder, { recursive: true });
    fs.writeFileSync(
        path.join(userData, 'User', 'settings.json'),
        JSON.stringify({
            'rpf.binaryPath': RPF,
            'window.restoreWindows': 'none',
            'workbench.enableExperiments': false,
            'telemetry.telemetryLevel': 'off',
            'update.mode': 'none',
        }),
    );
    const workspace = path.join(stage, 'rpf.code-workspace');
    fs.writeFileSync(workspace, JSON.stringify({ folders: [{ path: folder }] }));

    try {
        await launch(root, stage, workspace, userData);
    } finally {
        // The stage holds a user directory, an extensions directory and a
        // workspace file. The downloaded editor is not in it: that is in
        // `.vscode-test`, and re-downloading 300 MB per run is not a tidiness.
        fs.rmSync(stage, { recursive: true, force: true });
    }
}

/** One editor, run against this directory until its tests are done. */
async function launch(
    root: string,
    stage: string,
    workspace: string,
    userData: string,
): Promise<void> {
    await runTests({
        vscodeExecutablePath: executableOf(await downloadAndUnzipVSCode()),
        extensionDevelopmentPath: root,
        extensionTestsPath: path.resolve(__dirname, 'suite.js'),
        extensionTestsEnv: { RPF_BIN: RPF },
        launchArgs: [
            workspace,
            '--disable-extensions',
            '--disable-workspace-trust',
            '--disable-gpu',
            '--skip-welcome',
            '--skip-release-notes',
            '--user-data-dir',
            userData,
            '--extensions-dir',
            path.join(stage, 'extensions'),
        ],
    });
}

/** What the executable inside a downloaded VS Code has been called. */
const EXECUTABLES = ['Code', 'Electron', 'Code - Insiders'];

/**
 * The executable inside a downloaded VS Code.
 *
 * `@vscode/test-electron` 2.5.2 spells the macOS one
 * `Visual Studio Code.app/Contents/MacOS/Electron`, and VS Code 1.135.0 ships
 * it as `Code`. Measured against 1.135.0/darwin-arm64: the download succeeds
 * and the launch fails with `ENOENT`. So the names it has gone by are tried
 * beside the one that was asked for, and anything else in that directory —
 * `.DS_Store` is the one that turns up — is not a candidate.
 */
function executableOf(named: string): string {
    const directory = path.dirname(named);
    for (const candidate of [named, ...EXECUTABLES.map((one) => path.join(directory, one))]) {
        if (runnable(candidate)) {
            return candidate;
        }
    }
    throw new Error(`no VS Code executable at ${named}, nor as ${EXECUTABLES.join(', ')} beside it`);
}

/** Whether a path is a file this process may execute. */
function runnable(at: string): boolean {
    try {
        if (!fs.statSync(at).isFile()) {
            return false;
        }
        fs.accessSync(at, fs.constants.X_OK);
        return true;
    } catch {
        return false;
    }
}

main().catch((failure: unknown) => {
    console.error(failure instanceof Error ? failure.stack : String(failure));
    process.exitCode = 1;
});
