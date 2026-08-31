/**
 * What the tests need: a real `rpf` binary, and real archives built with it.
 *
 * Nothing here mocks the daemon. The only evidence available that this client
 * and the daemon agree is that they were made to talk to each other, so every
 * live test spawns `rpf serve --stdio` built from this repository and drives
 * it. A missing binary is a **skip naming what was skipped**, never a pass —
 * `docs/conventions.md` §12, which says exactly that about a missing corpus and
 * says it for the same reason.
 */

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

const run = promisify(execFile);

/** The archive-level encryption tag for an unencrypted archive: `OPEN`. */
export const ENCRYPTION_OPEN = 0x4e45504f;

/** Where this file runs from, so the repository root can be reached from it. */
const here = __dirname;

/** The binary under test, or `undefined` when there is none to test against. */
export const RPF: string | undefined = findBinary();

/**
 * Refuses a binary in `target/` that is older than the sources it was built
 * from.
 *
 * A missing binary is a skip; a **stale** one is a misconfiguration, and
 * `docs/conventions.md` §12 makes that a failure rather than a skip for the
 * same reason it does for a corpus variable pointed at the wrong directory.
 * Measured 2026-08-31: a `target/release/rpf` left over from an earlier commit
 * produced a 135/3 run that was read as a client regression and was nothing of
 * the kind. Loud is the whole point — the suite must not be able to pass, or
 * fail, against a binary that is not this tree.
 *
 * Only for a binary this file resolved itself. `RPF_BIN` is a deliberate
 * choice, and second-guessing it would break testing a released binary.
 */
function refuseStale(binaryPath: string): void {
    if (process.env.RPF_BIN) {
        return;
    }
    const root = path.resolve(here, '../../../..');
    const built = fs.statSync(binaryPath).mtimeMs;
    let newest = 0;
    let newestPath = '';
    const walk = (at: string): void => {
        for (const found of fs.readdirSync(at, { withFileTypes: true })) {
            const full = path.join(at, found.name);
            if (found.isDirectory()) {
                walk(full);
            } else if (found.isFile()) {
                const seen = fs.statSync(full).mtimeMs;
                if (seen > newest) {
                    newest = seen;
                    newestPath = full;
                }
            }
        }
    };
    walk(path.join(root, 'crates'));
    for (const also of ['Cargo.toml', 'Cargo.lock']) {
        const full = path.join(root, also);
        const seen = fs.statSync(full).mtimeMs;
        if (seen > newest) {
            newest = seen;
            newestPath = full;
        }
    }
    if (newest > built) {
        throw new Error(
            `${binaryPath} is older than ${newestPath}, so these tests would ` +
                'run against a binary that is not this tree. Run `cargo build ' +
                '--release` in the repository root, or set RPF_BIN to the ' +
                'binary you mean to test.',
        );
    }
}

/** Why the live tests are skipped, or `false` when they are not. */
export const SKIP: string | false = RPF
    ? false
    : 'no rpf binary: set RPF_BIN, or run `cargo build --release` in the repository root';

function findBinary(): string | undefined {
    const named = process.env.RPF_BIN;
    const candidates = named
        ? [named]
        : [
              path.resolve(here, '../../../../target/release/rpf'),
              path.resolve(here, '../../../../target/debug/rpf'),
          ];
    for (const candidate of candidates) {
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
        } catch {
            continue;
        }
        refuseStale(candidate);
        return candidate;
    }
    return undefined;
}

/** The binary, or a failure saying there is none. Live tests are skipped first. */
export function binary(): string {
    if (!RPF) {
        throw new Error(SKIP || 'no rpf binary');
    }
    return RPF;
}

/** A temporary directory that goes away with the process. */
export function scratch(name: string): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), `rpf-client-${name}-`));
}

/** One entry to put in an archive. */
export interface Entry {
    path: string;
    bytes: Uint8Array;
    class?: 'binary' | 'resource';
    storage?: 'stored' | 'deflate';
}

/** How an archive is described to {@link packArchive}. */
export interface ArchiveSpec {
    entries: Entry[];
    directories?: string[];
}

/**
 * Builds an archive with the tool itself, from a tree and its manifest.
 *
 * DR-004's sidecar is the documented way to say what a tree cannot — stored or
 * deflated, binary or resource — so a fixture is written the way the tool reads
 * one rather than by assembling bytes here.
 */
export async function packArchive(at: string, spec: ArchiveSpec): Promise<string> {
    const tree = `${at}.tree`;
    fs.mkdirSync(tree, { recursive: true });
    for (const entry of spec.entries) {
        const file = path.join(tree, entry.path);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, entry.bytes);
    }
    const directories = new Set(spec.directories ?? []);
    for (const entry of spec.entries) {
        const parent = path.posix.dirname(entry.path);
        if (parent !== '.') {
            directories.add(parent);
        }
    }
    const manifest = {
        schema: 1,
        encryption: ENCRYPTION_OPEN,
        directories: [...directories],
        entries: spec.entries.map((entry) => ({
            path: entry.path,
            class: entry.class ?? 'binary',
            storage: entry.storage ?? 'deflate',
            encryption: 0,
        })),
    };
    fs.writeFileSync(path.join(tree, '.rpf-manifest.json'), JSON.stringify(manifest, null, 2));
    await run(binary(), ['--json', 'pack', tree, at]);
    return at;
}

/**
 * A minimal but real `RBF` payload: one open element named `root`, and the
 * close that ends it.
 *
 * Hand-encoded from `docs/metadata-encodings.md` — magic, a descriptor
 * declaring the name, the element's two meaningless words and its attribute
 * count, then the `0xFFFF` close. It is a fixture rather than game data
 * (DR-006), and it exists so the client can be shown presenting a tokenised
 * entry as XML without knowing anything about the encoding itself.
 */
export function rbfBytes(name: string): Buffer {
    const named = Buffer.from(name, 'ascii');
    const length = Buffer.alloc(2);
    length.writeUInt16LE(named.length);
    return Buffer.concat([
        Buffer.from('RBF0', 'ascii'),
        Buffer.from([0x00, 0x00]), // descriptor 0, an open element
        length,
        named,
        Buffer.from([0, 0, 0, 0, 0, 0]), // two unknown words and no attributes
        Buffer.from([0xff, 0xff]), // close
    ]);
}

/** The XML {@link rbfBytes} converts to. */
export function rbfDocument(name: string): string {
    return `<?xml version="1.0" encoding="UTF-8"?>\n<${name}/>\n`;
}

/**
 * A minimal but real resource: an `RSC7` header whose flags describe one
 * 512-byte system page and no graphics pages, followed by a raw deflate stream
 * of exactly that.
 *
 * Copied in shape from `crates/rpf/tests/serve.rs`, which says why each field
 * reads as it does: `verify` reads the payload back against these flags, and
 * the top nibbles carry the header's version field.
 */
export function resourceBytes(): Buffer {
    const header = Buffer.alloc(16);
    header.write('RSC7', 0, 'ascii');
    header.writeUInt32LE(162, 4);
    header.writeUInt32LE(0xa8000000, 8);
    header.writeUInt32LE(0x20000000, 12);
    return Buffer.concat([header, zlib.deflateRawSync(Buffer.alloc(512))]);
}

/** Bytes that do not deflate smaller, so an edit of this length will not fit. */
export function incompressible(length: number): Buffer {
    return crypto.randomBytes(length);
}
