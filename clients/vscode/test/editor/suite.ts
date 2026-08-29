/**
 * The editor layer, exercised in a running editor. R7.1, R7.2, R7.3, R7.5.
 *
 * This is the half of the client `npm test` cannot reach: the filesystem
 * provider as the editor asks it questions, the commands as a person runs them,
 * and the `rpf:` URI as a workspace folder. Every question is asked through
 * `vscode.workspace.fs` and `vscode.commands`, which is what the explorer and
 * the command palette do, and every answer is checked **from outside the
 * editor** — `rpf cat`, `rpf ls` and `rpf verify` run against the file on disk,
 * so a passing test means the bytes landed, not that the client believes they
 * did.
 *
 * The sample archive is located through `RPF_CORPUS` and confirmed by its
 * `sha256` before it is trusted, and a missing corpus is a skip naming what was
 * skipped — `docs/conventions.md` §12, and `RPF_REQUIRE_CORPUS` turns that skip
 * into a failure. The rest of the suite packs its own archives with the tool
 * and runs everywhere.
 */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import * as vscode from 'vscode';

import { SCHEME, rootOf, uriOf } from '../../src/core/uri.js';
import { binary, packArchive, scratch } from '../support.js';

const tool = promisify(execFile);

/** The archive the fixture describes, and the bytes it describes them of. */
const SAMPLE = 'rmrp_bp16_meringls63amg24/dlc.rpf';
const SAMPLE_SHA256 = 'bdbc7553b0cada5667b77dd702bf8bee0b2b2642e15ed16d52f1e2ebd8041fff';

/** How long any one case may take before it is a failure, not a hang. */
const LIMIT = 180_000;

interface Case {
    name: string;
    run: () => Promise<void>;
}

const cases: Case[] = [];

/** Every directory this suite put on disk, so that it takes them away again. */
const staged: string[] = [];

function it(name: string, body: () => Promise<void>): void {
    cases.push({ name, run: body });
}

/** A scratch directory that goes when the suite does. */
function staging(name: string): string {
    const at = scratch(name);
    staged.push(at);
    return at;
}

/** Puts back what the suite staged, whether or not it passed. */
function unstage(): void {
    for (const at of staged) {
        try {
            fs.rmSync(at, { recursive: true, force: true });
        } catch (failure) {
            console.log(`# ${at} could not be removed: ${String(failure)}`);
        }
    }
}

/** Runs every case in one editor, in order, and reports what failed. */
export async function run(): Promise<void> {
    workflow();
    sample();
    let failed = 0;
    console.log(`1..${cases.length}`);
    try {
        for (const [index, one] of cases.entries()) {
            const started = Date.now();
            try {
                await limited(one.run(), one.name);
                console.log(`ok ${index + 1} - ${one.name} (${Date.now() - started}ms)`);
            } catch (failure) {
                failed += 1;
                console.log(`not ok ${index + 1} - ${one.name} (${Date.now() - started}ms)`);
                console.log(
                    indent(
                        failure instanceof Error
                            ? (failure.stack ?? failure.message)
                            : String(failure),
                    ),
                );
            }
        }
    } finally {
        unstage();
    }
    console.log(`# ${cases.length - failed} passed, ${failed} failed`);
    if (failed > 0) {
        throw new Error(`${failed} of ${cases.length} editor tests failed`);
    }
}

function limited<T>(work: Promise<T>, name: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(
            () => reject(new Error(`${name} did not finish within ${LIMIT}ms`)),
            LIMIT,
        );
        work.then(resolve, reject).finally(() => clearTimeout(timer));
    });
}

function indent(text: string): string {
    return text
        .split('\n')
        .map((line) => `  ${line}`)
        .join('\n');
}

/** The extension under development, as the editor holds it. */
function extension(): vscode.Extension<unknown> {
    const found = vscode.extensions.all.find(
        (candidate) => (candidate.packageJSON as { name?: string }).name === 'rpf',
    );
    assert.ok(found, 'the rpf extension is not loaded in this editor');
    return found;
}

/** The URI of one entry of a mounted archive, built the way the client builds it. */
function entryUri(archive: string, inside: string): vscode.Uri {
    return vscode.Uri.from(uriOf({ archive, inside }));
}

/** What the archive holds on disk, whatever the editor is showing. */
async function listed(archive: string, inside = ''): Promise<string[]> {
    const { stdout } = await tool(binary(), ['--json', 'ls', '--recursive', archive, inside], {
        maxBuffer: 16 * 1024 * 1024,
    });
    return (JSON.parse(stdout) as { path: string }[]).map((entry) => entry.path).sort();
}

/** One entry's bytes, read by the tool rather than by the client under test. */
async function contents(archive: string, inside: string): Promise<Buffer> {
    const { stdout } = await tool(binary(), ['cat', archive, inside], {
        encoding: 'buffer',
        maxBuffer: 64 * 1024 * 1024,
    });
    return stdout;
}

/** What `verify` reports, which is a report whether or not it was clean. */
interface Verified {
    entries_checked: number;
    problems: { path: string; reason: string }[];
}

/**
 * Reads every entry back, and says which did not.
 *
 * A `verify` that found anything **exits non-zero** — measured, exit 4 with the
 * whole report still on standard output — because an exit code names who has to
 * act (DR-010). So the failure is unwrapped rather than thrown: a helper that
 * let it through could only ever report a clean archive, and the one case it
 * exists for would arrive as `Command failed` with the problems discarded.
 */
async function verified(archive: string): Promise<Verified> {
    const answered = await tool(binary(), ['--json', 'verify', archive], {
        maxBuffer: 16 * 1024 * 1024,
    }).catch((failure: { stdout?: string }) => failure);
    const printed = typeof answered.stdout === 'string' ? answered.stdout : '';
    let report: unknown;
    try {
        report = JSON.parse(printed);
    } catch {
        throw answered instanceof Error ? answered : new Error(`verify printed ${printed}`);
    }
    return report as Verified;
}

/**
 * Mounts an archive through the command a person runs, and answers the path the
 * mount is under.
 *
 * The path is read back out of the folder the extension added rather than
 * resolved here: the daemon resolves it with `fs::canonicalize`, which on
 * Windows answers a verbatim `\\?\C:\…` path where Node's `realpath` answers
 * `C:\…`. A client that guessed would key every URI on a path nothing mounted.
 */
async function mount(archive: string): Promise<string> {
    const before = new Set(mountedPaths());
    await vscode.commands.executeCommand('rpf.mountArchive', vscode.Uri.file(archive));
    let added: string | undefined;
    await until(
        () => {
            added = mountedPaths().find((one) => !before.has(one));
            return added !== undefined;
        },
        () => `${archive} did not appear as a workspace folder; the window holds ${folders()}`,
    );
    assert.ok(added, 'no folder was added');
    assert.ok(
        added.endsWith(path.basename(archive)),
        `the folder that appeared is ${added}, which is not ${archive}`,
    );
    return added;
}

/** The archive behind every `rpf:` folder the window holds. */
function mountedPaths(): string[] {
    return (vscode.workspace.workspaceFolders ?? [])
        .filter((one) => one.uri.scheme === SCHEME)
        .map((one) => one.uri.query);
}

async function until(holds: () => boolean, complaint: () => string): Promise<void> {
    for (let attempt = 0; attempt < 200; attempt += 1) {
        if (holds()) {
            return;
        }
        await new Promise((wake) => setTimeout(wake, 50));
    }
    throw new Error(complaint());
}

/** The `sha256` of a file, read a block at a time. */
async function digestOf(file: string): Promise<string> {
    const digest = crypto.createHash('sha256');
    for await (const block of fs.createReadStream(file)) {
        digest.update(block as Buffer);
    }
    return digest.digest('hex');
}

/** Every folder the window holds, for a failure that has to say why. */
function folders(): string {
    const open = (vscode.workspace.workspaceFolders ?? []).map((one) => one.uri.toString());
    return open.length === 0 ? '(none)' : open.join(', ');
}

/** The names of the children of one directory, as the explorer would show them. */
async function children(uri: vscode.Uri): Promise<string[]> {
    const entries = await vscode.workspace.fs.readDirectory(uri);
    return entries.map(([name]) => name).sort();
}

function text(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('utf8');
}

/**
 * The whole workflow, on an archive the tool itself packs.
 *
 * Nested, because a nested archive is the common case rather than an edge one
 * (DR-021), and packed rather than taken from the corpus so that this half runs
 * with no game data present at all.
 */
function workflow(): void {
    const stage = staging('editor-workflow');
    let archive = '';
    let at = '';

    it('mounting an archive activates the extension and registers its commands', async () => {
        const inner = await packArchive(path.join(stage, 'inner.rpf'), {
            entries: [
                {
                    path: 'data/vehicles.meta',
                    bytes: Buffer.from('<vehicleClass>VC_SUPER</vehicleClass>\n'),
                },
            ],
        });
        archive = await packArchive(path.join(stage, 'outer.rpf'), {
            entries: [
                { path: 'content.xml', bytes: Buffer.from('<content/>\n') },
                { path: 'data/handling.meta', bytes: Buffer.from('<handling/>\n') },
                {
                    path: 'x64/vehicles.rpf',
                    bytes: fs.readFileSync(inner),
                    storage: 'stored',
                },
            ],
        });
        at = await mount(archive);
        assert.ok(extension().isActive, 'running a command did not activate the extension');

        // Contributed commands are in the palette before the extension is
        // loaded; they are in this list only once something registered them.
        const contributed = (
            extension().packageJSON as { contributes: { commands: { command: string }[] } }
        ).contributes.commands.map((one) => one.command);
        const registered = await vscode.commands.getCommands(true);
        for (const command of contributed) {
            assert.ok(registered.includes(command), `${command} is contributed but not registered`);
        }
    });

    it('the archive is a folder, and a nested archive is a folder inside it', async () => {
        assert.deepEqual(await children(entryUri(at, '')), ['content.xml', 'data', 'x64']);
        assert.deepEqual(await children(entryUri(at, 'x64')), ['vehicles.rpf']);
        const nested = await vscode.workspace.fs.stat(entryUri(at, 'x64/vehicles.rpf'));
        assert.equal(
            nested.type,
            vscode.FileType.Directory,
            'a nested archive is not shown as a folder',
        );
        assert.deepEqual(await children(entryUri(at, 'x64/vehicles.rpf/data')), ['vehicles.meta']);
    });

    it('an edit inside the nested archive buffers, and one save writes it', async () => {
        const uri = entryUri(at, 'x64/vehicles.rpf/data/vehicles.meta');
        const document = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(document);
        assert.ok(document.getText().includes('VC_SUPER'));

        const edit = new vscode.WorkspaceEdit();
        const found = document.getText().indexOf('VC_SUPER');
        edit.replace(
            uri,
            new vscode.Range(document.positionAt(found), document.positionAt(found + 8)),
            'VC_SEDAN',
        );
        assert.ok(await vscode.workspace.applyEdit(edit), 'the edit was not applied');
        assert.ok(await document.save(), 'saving the document did not buffer the edit');

        assert.ok(
            text(await contents(at, 'x64/vehicles.rpf/data/vehicles.meta')).includes('VC_SUPER'),
            'a buffered edit reached the archive before the save',
        );
        assert.equal(
            text(await vscode.workspace.fs.readFile(uri)).includes('VC_SEDAN'),
            true,
            'the buffered edit is not what the editor reads back',
        );

        await vscode.commands.executeCommand('rpf.previewSave');
        await vscode.commands.executeCommand('rpf.saveArchive');

        const written = text(await contents(at, 'x64/vehicles.rpf/data/vehicles.meta'));
        assert.ok(written.includes('VC_SEDAN'), 'the save did not reach the archive');
        assert.ok(!written.includes('VC_SUPER'), 'the old bytes are still there');
        assert.deepEqual((await verified(at)).problems, [], 'the archive does not verify');
    });

    it('a created file is shown before the save, and is in the archive after it', async () => {
        await vscode.workspace.fs.createDirectory(entryUri(at, 'data/added'));
        await vscode.workspace.fs.writeFile(
            entryUri(at, 'data/added/notes.txt'),
            Buffer.from('added by the editor\n'),
        );
        assert.deepEqual(await children(entryUri(at, 'data')), ['added', 'handling.meta']);
        assert.ok(
            !(await listed(at)).includes('data/added/notes.txt'),
            'a created entry reached the archive before the save',
        );
        await vscode.commands.executeCommand('rpf.saveArchive');
        assert.ok((await listed(at)).includes('data/added/notes.txt'));
        assert.equal(text(await contents(at, 'data/added/notes.txt')), 'added by the editor\n');
    });

    it('a rename is shown before the save, and is in the archive after it', async () => {
        await vscode.workspace.fs.rename(
            entryUri(at, 'data/added/notes.txt'),
            entryUri(at, 'data/added/renamed.txt'),
            { overwrite: false },
        );
        assert.deepEqual(await children(entryUri(at, 'data/added')), ['renamed.txt']);
        assert.ok(
            (await listed(at)).includes('data/added/notes.txt'),
            'a rename reached the archive before the save',
        );
        await vscode.commands.executeCommand('rpf.saveArchive');
        const rows = await listed(at);
        assert.ok(rows.includes('data/added/renamed.txt'));
        assert.ok(!rows.includes('data/added/notes.txt'));
    });

    it('a delete is shown before the save, and is gone from the archive after it', async () => {
        await vscode.workspace.fs.delete(entryUri(at, 'data/added/renamed.txt'), {
            recursive: false,
            useTrash: false,
        });
        assert.deepEqual(await children(entryUri(at, 'data/added')), []);
        assert.ok(
            (await listed(at)).includes('data/added/renamed.txt'),
            'a delete reached the archive before the save',
        );
        await vscode.commands.executeCommand('rpf.saveArchive');
        assert.ok(!(await listed(at)).includes('data/added/renamed.txt'));
        assert.deepEqual((await verified(at)).problems, []);
    });

    it('verifying and unmounting are the commands, and unmount releases the archive', async () => {
        await vscode.commands.executeCommand('rpf.verifyArchive');
        await vscode.commands.executeCommand('rpf.unmountArchive');
        const root = vscode.Uri.from(rootOf(at)).toString();
        await until(
            () =>
                !(vscode.workspace.workspaceFolders ?? []).some(
                    (one) => one.uri.toString() === root,
                ),
            () => `the folder outlived the unmount: the window holds ${folders()}`,
        );
        await assert.rejects(
            async () => vscode.workspace.fs.readDirectory(entryUri(at, '')),
            'an unmounted archive is still readable',
        );
    });
}

/** The sample archive, and the change the exit criterion is written about. */
function sample(): void {
    const corpus = process.env.RPF_CORPUS;
    const at = corpus ? path.join(corpus, SAMPLE) : undefined;
    const missing = !at
        ? 'RPF_CORPUS is not set, so the sample archive cannot be located'
        : !fs.existsSync(at)
          ? `${at} is not there`
          : undefined;
    if (missing || !at) {
        const complaint = `the sample-archive workflow was skipped: ${missing}`;
        if (process.env.RPF_REQUIRE_CORPUS) {
            it('the sample archive is present', () => Promise.reject(new Error(complaint)));
            return;
        }
        console.log(`# ${complaint}`);
        return;
    }

    const stage = staging('editor-sample');
    const copy = path.join(stage, 'dlc.rpf');
    let mounted = '';

    it('the sample archive is the one the fixture describes', async () => {
        // Streamed, and never `readFileSync`: this runs on the extension host's
        // own event loop, and 145 MB of synchronous reading blocks it long
        // enough that the editor restarts the host underneath the test.
        assert.equal(await digestOf(at), SAMPLE_SHA256, `${at} is not what the fixture describes`);
        // The corpus is never edited in place: DR-006's archives are read-only
        // evidence, and this test writes.
        await fs.promises.copyFile(at, copy);
    });

    it('the sample mounts, and the nested archive is a folder inside it', async () => {
        mounted = await mount(copy);
        assert.deepEqual(await children(entryUri(mounted, '')), [
            'content.xml',
            'data',
            'setup2.xml',
            'x64',
        ]);
        assert.ok((await children(entryUri(mounted, 'data'))).includes('vehicles.meta'));
        const nested = await vscode.workspace.fs.stat(entryUri(mounted, 'x64/vehicles.rpf'));
        assert.equal(nested.type, vscode.FileType.Directory);
        assert.deepEqual(await children(entryUri(mounted, 'x64/vehicles.rpf')), [
            'meringls63amg24.ytd',
            'meringls63amg24.yft',
            'meringls63amg24_hi.yft',
        ].sort());
    });

    it('VC_SUPER becomes VC_SEDAN in data/vehicles.meta, and the save writes it', async () => {
        const uri = entryUri(mounted, 'data/vehicles.meta');
        const before = await contents(mounted, 'data/vehicles.meta');
        const document = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(document);

        const found = document.getText().indexOf('VC_SUPER');
        assert.ok(found >= 0, 'the sample does not hold VC_SUPER');
        const edit = new vscode.WorkspaceEdit();
        edit.replace(
            uri,
            new vscode.Range(document.positionAt(found), document.positionAt(found + 8)),
            'VC_SEDAN',
        );
        assert.ok(await vscode.workspace.applyEdit(edit));
        assert.ok(await document.save());

        await vscode.commands.executeCommand('rpf.saveArchive');

        const after = await contents(mounted, 'data/vehicles.meta');
        assert.ok(after.includes('VC_SEDAN'), 'the edit did not reach the archive');
        assert.ok(!after.includes('VC_SUPER'));
        assert.equal(after.length, before.length, 'the editor changed more than the eight bytes');
        assert.deepEqual((await verified(mounted)).problems, [], 'the sample no longer verifies');
        await vscode.commands.executeCommand('rpf.unmountArchive');
    });
}
