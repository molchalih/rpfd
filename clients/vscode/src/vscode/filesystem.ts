/**
 * The `rpf:` filesystem, as the editor asks about one. R7.1.
 *
 * A thin adapter and nothing else: every question is answered out of
 * `core/session.ts` and `core/tree.ts`, which are tested against a live daemon,
 * and every failure is rendered by `core/errors.ts`. What is here that is not
 * there is exactly the editor's own vocabulary.
 *
 * **A write buffers.** `writeFile` is what the editor calls when a document is
 * saved, and it does not write the archive: it buffers the edit, and the
 * archive is written by the explicit `RPF: Save Archive` command. R7.3, and
 * DR-008's reason for it — a save decides between patching in place and
 * rebuilding for the whole set of edits, and a rebuild is unbounded work.
 */

import * as vscode from 'vscode';

import { type Node, isDirectory } from '../core/tree.js';
import { addressOf, uriOf } from '../core/uri.js';
import type { Archives, Mounted } from './archives.js';
import { asFileSystemError } from './messages.js';

/** Adding, deleting and renaming entries, which the daemon has no method for. */
const NO_ENTRY_CHANGES =
    'This extension can change what is in an entry, and cannot add, remove or rename one: the daemon has no method for it. Extract the archive, change the tree, and pack it again.';

/** The editor's view of an archive. */
export class RpfFileSystem implements vscode.FileSystemProvider {
    private readonly archives: Archives;
    private readonly changes = new vscode.EventEmitter<vscode.FileChangeEvent[]>();

    readonly onDidChangeFile = this.changes.event;

    constructor(archives: Archives) {
        this.archives = archives;
    }

    /**
     * Nothing is watched.
     *
     * The archive is the daemon's, one session at a time (DR-009), and nothing
     * else in this window can change it. What does change it — a save — fires
     * {@link changed} for itself.
     */
    watch(): vscode.Disposable {
        return new vscode.Disposable(() => undefined);
    }

    /** Tells the editor an archive's contents have moved under it. */
    changed(archive: string): void {
        const mount = this.archives.at(archive);
        if (!mount) {
            return;
        }
        this.changes.fire([
            {
                type: vscode.FileChangeType.Changed,
                uri: this.uriFor(archive, ''),
            },
        ]);
    }

    async stat(uri: vscode.Uri): Promise<vscode.FileStat> {
        const { mount, node } = await this.reach(uri);
        const buffered = mount.session.lengthOf(node.path);
        return {
            type: isDirectory(node) ? vscode.FileType.Directory : vscode.FileType.File,
            ctime: 0,
            mtime: mount.session.changedAt,
            size: isDirectory(node) ? 0 : (buffered ?? node.len),
        };
    }

    async readDirectory(uri: vscode.Uri): Promise<[string, vscode.FileType][]> {
        const { mount, node } = await this.reach(uri);
        if (!isDirectory(node)) {
            throw vscode.FileSystemError.FileNotADirectory(uri);
        }
        return mount.session.tree
            .childrenOf(node.path)
            .map((child) => [
                child.name,
                isDirectory(child) ? vscode.FileType.Directory : vscode.FileType.File,
            ]);
    }

    async readFile(uri: vscode.Uri): Promise<Uint8Array> {
        const { mount, node } = await this.reach(uri);
        if (isDirectory(node)) {
            throw vscode.FileSystemError.FileIsADirectory(uri);
        }
        try {
            return await mount.session.read(node.path);
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
    }

    /** Buffers an edit. The archive is written by an explicit save. R7.3. */
    async writeFile(
        uri: vscode.Uri,
        content: Uint8Array,
        options: { create: boolean; overwrite: boolean },
    ): Promise<void> {
        const { mount, address } = this.locate(uri);
        const node = mount.session.tree.at(address.inside);
        if (!node) {
            throw vscode.FileSystemError.NoPermissions(
                options.create ? NO_ENTRY_CHANGES : `${uri.toString()} is not in the archive`,
            );
        }
        if (isDirectory(node)) {
            throw vscode.FileSystemError.FileIsADirectory(uri);
        }
        try {
            await mount.session.write(node.path, content);
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
        this.changes.fire([{ type: vscode.FileChangeType.Changed, uri }]);
    }

    /** Refused: the daemon has no method that changes the entry table. */
    delete(): void {
        throw vscode.FileSystemError.NoPermissions(NO_ENTRY_CHANGES);
    }

    /** Refused, for the reason {@link delete} is. */
    rename(): void {
        throw vscode.FileSystemError.NoPermissions(NO_ENTRY_CHANGES);
    }

    /** Refused, for the reason {@link delete} is. */
    createDirectory(): void {
        throw vscode.FileSystemError.NoPermissions(NO_ENTRY_CHANGES);
    }

    /** The URI of one entry inside a mounted archive. */
    uriFor(archive: string, inside: string): vscode.Uri {
        return vscode.Uri.from(uriOf({ archive, inside }));
    }

    /** Which mounted archive and which entry a URI names. */
    private locate(uri: vscode.Uri): {
        mount: Mounted;
        address: { archive: string; inside: string };
    } {
        let address;
        try {
            address = addressOf({
                scheme: uri.scheme,
                authority: uri.authority,
                path: uri.path,
                query: uri.query,
            });
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
        const mount = this.archives.at(address.archive);
        if (!mount) {
            throw vscode.FileSystemError.Unavailable(
                `${address.archive} is not mounted. Run "RPF: Mount Archive as Folder" on it.`,
            );
        }
        return { mount, address };
    }

    private async reach(uri: vscode.Uri): Promise<{ mount: Mounted; node: Node }> {
        const { mount, address } = this.locate(uri);
        const node = mount.session.tree.at(address.inside);
        if (!node) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        return await Promise.resolve({ mount, node });
    }
}
