/** A buffered edit, badged on the entry it was made to. */

import * as vscode from 'vscode';

import { SCHEME, uriOf } from '../core/uri.js';
import type { Archives } from './archives.js';
import { markOf } from './marks.js';

/**
 * The badge on every path with a buffered change.
 *
 * It propagates, so a folder carries what is waiting inside it and an edit made
 * deep in an archive is visible from the root without opening anything.
 */
export class Decorations implements vscode.FileDecorationProvider {
    private readonly archives: Archives;
    private marked = new Map<string, { uri: vscode.Uri; decoration: vscode.FileDecoration }>();
    private readonly changed = new vscode.EventEmitter<vscode.Uri[]>();
    private readonly watching: vscode.Disposable;

    readonly onDidChangeFileDecorations = this.changed.event;

    constructor(archives: Archives) {
        this.archives = archives;
        this.watching = archives.onDidChange(() => this.refresh());
    }

    provideFileDecoration(uri: vscode.Uri): vscode.FileDecoration | undefined {
        return uri.scheme === SCHEME ? this.marked.get(uri.toString())?.decoration : undefined;
    }

    dispose(): void {
        this.watching.dispose();
        this.changed.dispose();
    }

    // Announced for what it held as well as what it holds: a commit leaves the
    // archive clean, and the badges it wore have to be taken back.
    private refresh(): void {
        const before = this.marked;
        this.marked = new Map();
        for (const mount of this.archives.all()) {
            for (const one of mount.session.dirtyChanges()) {
                const mark = markOf(one);
                const uri = vscode.Uri.from(
                    uriOf({ archive: mount.session.path, inside: one.path }),
                );
                this.marked.set(uri.toString(), {
                    uri,
                    decoration: {
                        badge: mark.badge,
                        tooltip: mark.tooltip,
                        color: new vscode.ThemeColor(mark.color),
                        propagate: true,
                    },
                });
            }
        }
        const touched = new Map([...before, ...this.marked]);
        if (touched.size > 0) {
            this.changed.fire([...touched.values()].map((one) => one.uri));
        }
    }
}
