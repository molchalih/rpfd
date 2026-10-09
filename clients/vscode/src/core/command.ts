/**
 * The `rpf` command outside the extension: a copy of the binary at a stable
 * per-user path, which this extension replaces or removes only while it is the
 * copy it put there.
 */

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { binaryName, isExecutable, pathEntries, probeVersion, type Located } from './locate.js';

/**
 * What records the copy: its SHA-256 and the extension version, beside it, so
 * the extension and its uninstall script both find it from the copy's path.
 */
export const MARKER = '.rpf-command.json';

/** How a line this extension adds to a shell profile is marked. */
export const TAG = '# added by RPF Archives';

/** The machine a layout is worked out for. */
export interface Host {
    platform: NodeJS.Platform;
    home: string;
    env: Record<string, string | undefined>;
}

/** Where the copy goes, and what records it. */
export interface Layout {
    directory: string;
    binary: string;
    marker: string;
    /** Whether the directory is this extension's alone, and goes when it is empty. */
    owned: boolean;
}

/** What installing did. */
export type Installed =
    | { done: 'installed' | 'replaced' | 'unchanged'; at: string }
    | { done: 'refused'; at: string; holds: string };

/** What uninstalling did. */
export type Removed =
    | { done: 'removed' | 'absent'; at: string }
    | { done: 'refused'; at: string; holds: string };

/** A shell profile, and the one line this extension would add to it. */
export interface Profile {
    file: string;
    line: string;
}

/** The marker's content. While a copy is being replaced it accepts both digests. */
interface Marked {
    sha256: string[];
    version: string;
}

type Probe = (binary: string) => Promise<string | undefined>;

/** The machine this process runs on. */
export function currentHost(): Host {
    return { platform: process.platform, home: os.homedir(), env: process.env };
}

/** A layout in a given directory. */
export function layoutAt(
    directory: string,
    owned: boolean,
    platform: NodeJS.Platform = process.platform,
): Layout {
    const paths = platform === 'win32' ? path.win32 : path.posix;
    return {
        directory,
        binary: paths.join(directory, binaryName(platform)),
        marker: paths.join(directory, MARKER),
        owned,
    };
}

/** `~/.local/bin/rpf`, or `%LOCALAPPDATA%\Programs\rpf\rpf.exe`. */
export function layoutFor(host: Host): Layout {
    if (host.platform === 'win32') {
        const local = host.env.LOCALAPPDATA || path.win32.join(host.home, 'AppData', 'Local');
        return layoutAt(path.win32.join(local, 'Programs', 'rpf'), true, 'win32');
    }
    return layoutAt(path.posix.join(host.home, '.local', 'bin'), false, host.platform);
}

/**
 * What to prepend to `PATH` in the editor's terminals: the bundled binary's own
 * folder, and only when no `rpf` on `pathVariable` would answer instead.
 */
export function terminalPathFor(
    found: Located,
    pathVariable: string | undefined,
    platform: NodeJS.Platform = process.platform,
    executable: (at: string) => boolean = isExecutable,
): string | undefined {
    if (!found.found || found.source !== 'bundled') {
        return undefined;
    }
    const paths = platform === 'win32' ? path.win32 : path.posix;
    const name = binaryName(platform);
    if (pathEntries(pathVariable, platform).some((directory) => executable(paths.join(directory, name)))) {
        return undefined;
    }
    return `${paths.dirname(found.path)}${paths.delimiter}`;
}

/**
 * The binary to copy, or nothing: one found on `PATH` is a command already,
 * and a second copy of it would only shadow or be shadowed by the first.
 */
export function installable(found: Located): string | undefined {
    return found.found && found.source !== 'path' ? found.path : undefined;
}

/** Whether a directory is one of the entries of a `PATH` value. */
export function onPath(
    directory: string,
    pathVariable: string | undefined,
    platform: NodeJS.Platform = process.platform,
    home?: string,
): boolean {
    const windows = platform === 'win32';
    const paths = windows ? path.win32 : path.posix;
    const canonical = (entry: string): string => {
        let at = windows ? entry.replace(/^"(.*)"$/, '$1') : entry;
        if (!windows && home !== undefined && (at === '~' || at.startsWith('~/'))) {
            at = paths.join(home, at.slice(1));
        }
        at = paths.normalize(at);
        if (at.length > paths.parse(at).root.length) {
            at = at.replace(/[\\/]+$/, '');
        }
        return windows ? at.toLowerCase() : at;
    };
    const wanted = canonical(directory);
    return pathEntries(pathVariable, platform).some((entry) => canonical(entry) === wanted);
}

/**
 * The startup file of the user's shell, or nothing for a shell this does not
 * know how to edit. The line names {@link layoutFor}'s directory.
 *
 * Bash on macOS reads `~/.bash_profile` and then not `~/.profile`, so creating
 * the first where only the second exists would hide it; that one is used instead.
 */
export function profileFor(
    host: Host,
    exists: (file: string) => boolean = existsSync,
): Profile | undefined {
    if (host.platform === 'win32') {
        return undefined;
    }
    const join = path.posix.join;
    const relative = path.posix.relative(host.home, layoutFor(host).directory);
    const directory = relative.startsWith('..') ? layoutFor(host).directory : `$HOME/${relative}`;
    const exported = `export PATH="${directory}:$PATH"  ${TAG}`;
    switch (path.posix.basename(host.env.SHELL ?? '')) {
        case 'zsh':
            return { file: join(host.env.ZDOTDIR || host.home, '.zshrc'), line: exported };
        case 'bash': {
            if (host.platform !== 'darwin') {
                return { file: join(host.home, '.bashrc'), line: exported };
            }
            const login = join(host.home, '.bash_profile');
            const plain = join(host.home, '.profile');
            return { file: !exists(login) && exists(plain) ? plain : login, line: exported };
        }
        case 'fish': {
            const config = host.env.XDG_CONFIG_HOME || join(host.home, '.config');
            return {
                file: join(config, 'fish', 'conf.d', 'rpf.fish'),
                line: `fish_add_path --path "${directory}"  ${TAG}`,
            };
        }
        default:
            return undefined;
    }
}

/** Whether the profile already carries this extension's line. */
export async function profileHolds(profile: Profile): Promise<boolean> {
    return linesOf(await textOf(profile.file)).includes(profile.line);
}

/** Appends the line once; a profile that has it is left as it is. */
export async function addToProfile(profile: Profile): Promise<'added' | 'present'> {
    const text = await textOf(profile.file);
    if (linesOf(text).includes(profile.line)) {
        return 'present';
    }
    await fs.mkdir(path.dirname(profile.file), { recursive: true });
    const gap = text.length > 0 && !text.endsWith('\n') ? '\n' : '';
    await fs.appendFile(profile.file, `${gap}${profile.line}\n`);
    return 'added';
}

/**
 * The PowerShell run that adds a directory to the *user* `PATH`, printing
 * `added` or `present`.
 *
 * Read and written through the registry with the value's own kind, because
 * `SetEnvironmentVariable` writes `REG_SZ` and would stop `%USERPROFILE%`-style
 * entries expanding; it is then called on a scratch variable for its broadcast.
 */
export function userPathCommand(directory: string): { command: string; args: string[] } {
    // PowerShell ends a single-quoted string at any of the four single quotes.
    const quoted = `'${directory.replace(/['‘-‛]/g, '$&$&')}'`;
    const script = [
        "$ErrorActionPreference = 'Stop'",
        `$dir = ${quoted}`,
        "$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')",
        "$raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)",
        "$kind = if ($key.GetValueNames() -contains 'Path') { $key.GetValueKind('Path') } else { [Microsoft.Win32.RegistryValueKind]::ExpandString }",
        "$parts = @($raw -split ';' | Where-Object { $_ -ne '' })",
        "if ($parts | Where-Object { [Environment]::ExpandEnvironmentVariables($_.Trim('\"')).TrimEnd('\\') -ieq $dir.TrimEnd('\\') }) { 'present'; exit 0 }",
        "$key.SetValue('Path', (($parts + $dir) -join ';'), $kind)",
        "[Environment]::SetEnvironmentVariable('RPF_PATH_CHANGED', '1', 'User')",
        "[Environment]::SetEnvironmentVariable('RPF_PATH_CHANGED', $null, 'User')",
        "'added'",
    ].join('\n');
    return {
        command: 'powershell.exe',
        args: [
            '-NoProfile',
            '-NonInteractive',
            '-EncodedCommand',
            Buffer.from(script, 'utf16le').toString('base64'),
        ],
    };
}

/**
 * Copies `source`, from extension `version`, into the layout — unless something
 * it did not put there is in the way.
 */
export async function install(
    source: string,
    version: string,
    layout: Layout,
    probe: Probe = probeVersion,
): Promise<Installed> {
    const held = await heldAt(layout);
    if (held.by === 'other') {
        return { done: 'refused', at: layout.binary, holds: await holding(layout.binary, probe) };
    }
    if (held.by === 'us' && held.sha256 === (await digestOf(source))) {
        return { done: 'unchanged', at: layout.binary };
    }
    await place(source, version, layout, held.by === 'us' ? held : undefined);
    return { done: held.by === 'us' ? 'replaced' : 'installed', at: layout.binary };
}

/**
 * Replaces the copy with `source` when the copy is still one this extension
 * put there and `version` is newer than the one recorded. Answers whether it did.
 */
export async function refresh(source: string, version: string, layout: Layout): Promise<boolean> {
    const held = await heldAt(layout);
    if (held.by !== 'us' || !isNewer(version, held.version)) {
        return false;
    }
    const sha256 = await digestOf(source);
    if (sha256 === held.sha256) {
        await record(layout, { sha256: [sha256], version });
        return false;
    }
    await place(source, version, layout, held);
    return true;
}

/** Removes the copy and its record, if the copy is still one this extension put there. */
export async function uninstall(layout: Layout, probe: Probe = probeVersion): Promise<Removed> {
    const held = await heldAt(layout);
    const holds = held.by === 'other' ? await holding(layout.binary, probe) : '';
    if (held.by === 'us') {
        await fs.rm(layout.binary);
    }
    await fs.rm(layout.marker, { force: true });
    if (layout.owned) {
        await fs.rmdir(layout.directory).catch((failure: NodeJS.ErrnoException) => {
            if (!['ENOENT', 'ENOTEMPTY', 'EEXIST'].includes(failure.code ?? '')) {
                throw failure;
            }
        });
    }
    if (held.by === 'other') {
        return { done: 'refused', at: layout.binary, holds };
    }
    return { done: held.by === 'us' ? 'removed' : 'absent', at: layout.binary };
}

/**
 * Whether `candidate` is a later semantic version than `than`. Anything that
 * does not parse is not later, so an unreadable record is never replaced.
 */
export function isNewer(candidate: string, than: string): boolean {
    const one = parseVersion(candidate);
    const other = parseVersion(than);
    if (one === undefined || other === undefined) {
        return false;
    }
    for (const [mine, theirs] of one.core.map((part, at) => [part, other.core[at] ?? 0] as const)) {
        if (mine !== theirs) {
            return mine > theirs;
        }
    }
    if (one.pre.length === 0 || other.pre.length === 0) {
        return one.pre.length === 0 && other.pre.length > 0;
    }
    for (let at = 0; at < Math.max(one.pre.length, other.pre.length); at += 1) {
        const mine = one.pre[at];
        const theirs = other.pre[at];
        if (mine === undefined || theirs === undefined) {
            return theirs === undefined;
        }
        if (mine !== theirs) {
            const numeric = /^\d+$/.test(mine) && /^\d+$/.test(theirs);
            if (numeric) {
                return Number(mine) > Number(theirs);
            }
            if (/^\d+$/.test(mine) || /^\d+$/.test(theirs)) {
                return /^\d+$/.test(theirs);
            }
            return mine > theirs;
        }
    }
    return false;
}

function parseVersion(version: string): { core: number[]; pre: string[] } | undefined {
    const parts = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version.trim());
    if (parts === null) {
        return undefined;
    }
    return {
        core: [Number(parts[1]), Number(parts[2]), Number(parts[3])],
        pre: parts[4] === undefined ? [] : parts[4].split('.'),
    };
}

type Held = { by: 'nobody' } | { by: 'us'; sha256: string; version: string } | { by: 'other' };

/** Who the file at the layout's binary path belongs to. A link is never ours. */
async function heldAt(layout: Layout): Promise<Held> {
    let seen;
    try {
        seen = await fs.lstat(layout.binary);
    } catch (failure) {
        if ((failure as NodeJS.ErrnoException).code === 'ENOENT') {
            return { by: 'nobody' };
        }
        throw failure;
    }
    const recorded = seen.isFile() ? await recordOf(layout.marker) : undefined;
    if (recorded === undefined) {
        return { by: 'other' };
    }
    const sha256 = await digestOf(layout.binary);
    return recorded.sha256.includes(sha256)
        ? { by: 'us', sha256, version: recorded.version }
        : { by: 'other' };
}

/** What is at a path this extension did not put there, in words. */
async function holding(at: string, probe: Probe): Promise<string> {
    const seen = await fs.lstat(at);
    if (seen.isSymbolicLink()) {
        return `a link to ${await fs.readlink(at)}`;
    }
    if (!seen.isFile()) {
        return 'something that is not a file';
    }
    return (await probe(at)) ?? 'a file that does not answer --version as rpf';
}

/**
 * Copies through a partial file and a rename. The record accepts the old and
 * the new digest across the rename, so a crash there leaves a copy still ours.
 */
async function place(
    source: string,
    version: string,
    layout: Layout,
    previous: { sha256: string; version: string } | undefined,
): Promise<void> {
    await fs.mkdir(layout.directory, { recursive: true });
    const partial = `${layout.binary}.${process.pid}.partial`;
    try {
        await fs.copyFile(source, partial);
        await fs.chmod(partial, 0o755);
        const sha256 = await digestOf(partial);
        await record(layout, {
            sha256: previous === undefined ? [sha256] : [previous.sha256, sha256],
            version: previous?.version ?? version,
        });
        await fs.rename(partial, layout.binary);
        if ((await digestOf(layout.binary)) !== sha256) {
            throw new Error(`${layout.binary} changed while it was being installed`);
        }
        await record(layout, { sha256: [sha256], version });
    } finally {
        await fs.rm(partial, { force: true });
    }
}

/** Writes the marker through a partial file and a rename. */
async function record(layout: Layout, content: Marked): Promise<void> {
    const partial = `${layout.marker}.${process.pid}.partial`;
    try {
        await fs.writeFile(partial, `${JSON.stringify(content)}\n`);
        await fs.rename(partial, layout.marker);
    } finally {
        await fs.rm(partial, { force: true });
    }
}

/** What a marker records, or nothing for a marker absent or unreadable. */
async function recordOf(marker: string): Promise<Marked | undefined> {
    try {
        const parsed = JSON.parse(await fs.readFile(marker, 'utf8')) as Partial<Marked>;
        const { sha256, version } = parsed;
        if (!Array.isArray(sha256) || !sha256.every((one) => typeof one === 'string')) {
            return undefined;
        }
        return typeof version === 'string' ? { sha256, version } : undefined;
    } catch {
        return undefined;
    }
}

async function digestOf(file: string): Promise<string> {
    const digest = createHash('sha256');
    for await (const block of createReadStream(file)) {
        digest.update(block as Buffer);
    }
    return digest.digest('hex');
}

async function textOf(file: string): Promise<string> {
    try {
        return await fs.readFile(file, 'utf8');
    } catch (failure) {
        if ((failure as NodeJS.ErrnoException).code === 'ENOENT') {
            return '';
        }
        throw failure;
    }
}

function linesOf(text: string): string[] {
    return text.split(/\r?\n/);
}
