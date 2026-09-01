/**
 * Finding the `rpf` binary, and saying what to do when there is none.
 *
 * Three places, in the order a user would expect them to win: what they
 * configured, what shipped with the extension, and what is on `PATH`. Each
 * candidate is proved by running it — a file called `rpf` that is not this tool
 * fails later and less clearly than no file at all.
 */

import { execFile } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import path from 'node:path';

/** Where a binary was found. */
export type Source = 'setting' | 'bundled' | 'path';

/** One place that was looked, and what was there. */
export interface Attempt {
    source: Source;
    at: string;
    /** Why it was not used. */
    why: string;
}

/** The outcome of looking. */
export type Located =
    | { found: true; path: string; source: Source; version: string }
    | { found: false; tried: Attempt[]; instructions: string };

/** What to look with. */
export interface Search {
    /** The `rpf.binaryPath` setting, if the user set one. */
    setting?: string | undefined;
    /** The extension's own directory, which is where a bundled binary sits. */
    extensionRoot?: string | undefined;
    /** `PATH`, as the environment gives it. */
    pathVariable?: string | undefined;
    platform?: NodeJS.Platform;
    arch?: string;
    /** Runs a candidate and reports its version, or `undefined` if it is not one. */
    probe?: (binary: string) => Promise<string | undefined>;
}

/** What a bundled binary is called on this platform. */
export function binaryName(platform: NodeJS.Platform = process.platform): string {
    return platform === 'win32' ? 'rpf.exe' : 'rpf';
}

/** Where a bundled binary would be. One directory per target. */
export function bundledAt(
    extensionRoot: string,
    platform: NodeJS.Platform = process.platform,
    arch: string = process.arch,
): string {
    return path.join(extensionRoot, 'bin', `${platform}-${arch}`, binaryName(platform));
}

/** Every candidate, in the order they are tried. */
export function candidates(search: Search): { source: Source; at: string }[] {
    const platform = search.platform ?? process.platform;
    const arch = search.arch ?? process.arch;
    const found: { source: Source; at: string }[] = [];
    if (search.setting && search.setting.trim().length > 0) {
        found.push({ source: 'setting', at: search.setting.trim() });
    }
    if (search.extensionRoot) {
        found.push({ source: 'bundled', at: bundledAt(search.extensionRoot, platform, arch) });
    }
    const name = binaryName(platform);
    const separator = platform === 'win32' ? ';' : ':';
    for (const directory of (search.pathVariable ?? '').split(separator)) {
        if (directory.trim().length === 0) {
            continue;
        }
        found.push({ source: 'path', at: path.join(directory, name) });
    }
    return found;
}

/** Whether a path is there and can be executed. */
export function isExecutable(at: string): boolean {
    try {
        accessSync(at, constants.X_OK);
        return true;
    } catch {
        return false;
    }
}

/**
 * Runs a candidate and reports the version it prints.
 *
 * `undefined` for anything that is not this tool, executable or not.
 */
export function probeVersion(binary: string): Promise<string | undefined> {
    return new Promise((settle) => {
        execFile(binary, ['--version'], { timeout: 10_000 }, (failure, stdout) => {
            if (failure) {
                settle(undefined);
                return;
            }
            const said = stdout.trim();
            settle(said.startsWith('rpf ') ? said : undefined);
        });
    });
}

/** Finds the binary, or says where it looked and what the user should do. */
export async function locate(search: Search = {}): Promise<Located> {
    const probe = search.probe ?? probeVersion;
    const tried: Attempt[] = [];
    for (const candidate of candidates(search)) {
        if (!isExecutable(candidate.at)) {
            tried.push({ ...candidate, why: 'nothing executable is there' });
            continue;
        }
        const version = await probe(candidate.at);
        if (version === undefined) {
            tried.push({ ...candidate, why: 'it is executable but does not answer --version as rpf' });
            continue;
        }
        return { found: true, path: candidate.at, source: candidate.source, version };
    }
    return { found: false, tried, instructions: instructionsFor(tried) };
}

/** What to tell a user who has no binary. */
function instructionsFor(tried: Attempt[]): string {
    const looked =
        tried.length === 0
            ? '  (nowhere — PATH was empty and no path was configured)'
            : tried.map((attempt) => `  ${attempt.at} — ${attempt.why}`).join('\n');
    return [
        'The rpf binary was not found, so no archive can be opened.',
        '',
        'Looked in:',
        looked,
        '',
        'Do one of these:',
        '  • Set "rpf.binaryPath" in your settings to the binary\'s absolute path.',
        '  • Put rpf on your PATH — it is one static binary with no runtime prerequisite.',
        '  • Build it from the repository: cargo build --release, then use target/release/rpf.',
    ].join('\n');
}
