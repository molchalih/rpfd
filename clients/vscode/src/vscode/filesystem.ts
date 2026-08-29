/**
 * The `rpf:` filesystem, as the editor asks about one. R7.1.
 *
 * A thin adapter and nothing else: every question is answered out of
 * `core/session.ts`, `core/pending.ts` and `core/tree.ts`, which are tested
 * against a live daemon, and every failure is rendered by `core/errors.ts`.
 * What is here that is not there is exactly the editor's own vocabulary.
 *
 * **A change buffers.** `writeFile`, `delete`, `rename` and `createDirectory`
 * do not write the archive: they buffer, and the archive is written by the
 * explicit `RPF: Save Archive` command. R7.3, DR-026, and DR-008's reason for
 * it — a save decides between patching in place and rebuilding for the whole
 * set of changes, and a rebuild is unbounded work.
 *
 * **The explorer is shown the session's view, not the daemon's listing.**
 * DR-028: `list` answers the archive on disk, so a provider that forwarded it
 * would show a created entry as absent and a deleted one as present until the
 * save. The session models the buffered structure itself, and this file fires
 * the events that make the editor ask again. DR-030.
 */

import * as vscode from 'vscode';

import { type Node, isDirectory } from '../core/tree.js';
import { addressOf, split, uriOf } from '../core/uri.js';
import type { Archives, Mounted } from './archives.js';
import { asFileSystemError } from './messages.js';

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
     * else in this window can change it. What does change it — a buffered
     * change, or a save — fires {@link changed} or its own event for itself.
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
        return {
            type: isDirectory(node) ? vscode.FileType.Directory : vscode.FileType.File,
            ctime: 0,
            mtime: mount.session.changedAt,
            size: isDirectory(node) ? 0 : node.len,
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

    /** Buffers a write, creating the entry when asked to. R7.3, DR-026. */
    async writeFile(
        uri: vscode.Uri,
        content: Uint8Array,
        options: { create: boolean; overwrite: boolean },
    ): Promise<void> {
        const { mount, address } = this.locate(uri);
        const node = mount.session.tree.at(address.inside);
        if (node && isDirectory(node)) {
            throw vscode.FileSystemError.FileIsADirectory(uri);
        }
        if (!node && !options.create) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        if (node && !options.overwrite) {
            throw vscode.FileSystemError.FileExists(uri);
        }
        if (!node) {
            this.requireDirectory(uri, address.inside);
        }
        try {
            await mount.session.write(address.inside, content, { create: options.create });
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
        this.announce(address.archive, address.inside, node ? 'changed' : 'created');
    }

    /** Buffers a removal. The archive is written by an explicit save. DR-026. */
    async delete(uri: vscode.Uri, options: { recursive: boolean }): Promise<void> {
        const { mount, address } = this.locate(uri);
        if (!mount.session.tree.at(address.inside)) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        try {
            await mount.session.remove(address.inside, { recursive: options.recursive });
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
        this.announce(address.archive, address.inside, 'deleted');
    }

    /**
     * Buffers a rename.
     *
     * `overwrite` has no answer here and is refused rather than approximated:
     * DR-026 gives a rename no override, because removing the target in the
     * same change set says the same thing out loud and shows up in the plan —
     * and the wire cannot carry even that, since a rename is resolved against
     * the archive on disk. DR-030.
     */
    async rename(from: vscode.Uri, to: vscode.Uri, options: { overwrite: boolean }): Promise<void> {
        const source = this.locate(from);
        const target = this.locate(to);
        if (source.address.archive !== target.address.archive) {
            throw vscode.FileSystemError.NoPermissions(
                'An entry can only be moved within the archive that holds it.',
            );
        }
        if (!source.mount.session.tree.at(source.address.inside)) {
            throw vscode.FileSystemError.FileNotFound(from);
        }
        if (source.mount.session.tree.at(target.address.inside)) {
            throw options.overwrite
                ? vscode.FileSystemError.NoPermissions(
                      `${target.address.inside} is already in the archive. A rename inside an archive has no overwrite: delete that entry, save the archive, then rename.`,
                  )
                : vscode.FileSystemError.FileExists(to);
        }
        this.requireDirectory(to, target.address.inside);
        try {
            await source.mount.session.rename(source.address.inside, target.address.inside);
        } catch (failure) {
            throw asFileSystemError(failure, to);
        }
        this.announce(source.address.archive, source.address.inside, 'deleted');
        this.announce(target.address.archive, target.address.inside, 'created');
    }

    /** Buffers a directory. DR-026. */
    async createDirectory(uri: vscode.Uri): Promise<void> {
        const { mount, address } = this.locate(uri);
        if (mount.session.tree.at(address.inside)) {
            throw vscode.FileSystemError.FileExists(uri);
        }
        this.requireDirectory(uri, address.inside);
        try {
            await mount.session.makeDirectory(address.inside);
        } catch (failure) {
            throw asFileSystemError(failure, uri);
        }
        this.announce(address.archive, address.inside, 'created');
    }

    /** The URI of one entry inside a mounted archive. */
    uriFor(archive: string, inside: string): vscode.Uri {
        return vscode.Uri.from(uriOf({ archive, inside }));
    }

    /**
     * Says a path appeared, went, or changed, and that its parent listing did.
     *
     * The parent as well as the path itself: an explorer asks a directory for
     * its children again when the directory changes, and a creation is a change
     * to the directory that now holds it.
     */
    private announce(archive: string, inside: string, what: 'created' | 'deleted' | 'changed'): void {
        const type =
            what === 'created'
                ? vscode.FileChangeType.Created
                : what === 'deleted'
                  ? vscode.FileChangeType.Deleted
                  : vscode.FileChangeType.Changed;
        const events: vscode.FileChangeEvent[] = [{ type, uri: this.uriFor(archive, inside) }];
        if (what !== 'changed') {
            events.push({
                type: vscode.FileChangeType.Changed,
                uri: this.uriFor(archive, split(inside).parent),
            });
        }
        this.changes.fire(events);
    }

    /** Refuses a path whose parent is not a directory this archive holds. */
    private requireDirectory(uri: vscode.Uri, inside: string): void {
        const { parent } = split(inside);
        if (parent.length === 0) {
            return;
        }
        const { mount } = this.locate(uri);
        const node = mount.session.tree.at(parent);
        if (!node) {
            throw vscode.FileSystemError.FileNotFound(uri);
        }
        if (!isDirectory(node)) {
            throw vscode.FileSystemError.FileNotADirectory(uri);
        }
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
