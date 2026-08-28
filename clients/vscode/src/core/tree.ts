/**
 * The archive's shape, as one recursive listing describes it.
 *
 * The daemon's `list` reports the same rows `rpf --json ls` prints, and a
 * recursive one walks through nesting: an archive holding `x64/inner.rpf`
 * reports that entry *and* `x64/inner.rpf/data/vehicles.meta` beneath it. So a
 * nested archive is not recognised here by its name or its first four bytes —
 * it is recognised by the daemon having listed something inside it, which is
 * the only reading of "this is an archive" that this client is entitled to
 * (`docs/conventions.md` §1).
 *
 * One listing rather than one per directory: an editor asks for a file's kind
 * and size far more often than an archive changes, and the alternative — a
 * round trip per directory opened — cannot tell a nested archive from a plain
 * entry without a second round trip per entry.
 */

import type { Listed } from './protocol.js';
import { normalise, split } from './uri.js';

/** What a node is. */
export type NodeKind = 'directory' | 'binary' | 'resource' | 'archive';

/** One entry or directory in the archive. */
export interface Node {
    /** The name within its parent. Empty for the root. */
    name: string;
    /** The whole path inside the archive. Empty for the root. */
    path: string;
    kind: NodeKind;
    /** A file's length in bytes. Zero for a directory. */
    len: number;
    children: Map<string, Node>;
}

/** Whether a node holds other nodes. */
export function isDirectory(node: Node): boolean {
    return node.kind === 'directory' || node.kind === 'archive';
}

/** The archive's tree, built from one recursive listing. */
export class Tree {
    private readonly root: Node;

    private constructor(root: Node) {
        this.root = root;
    }

    /** Builds the tree the rows describe. */
    static of(rows: readonly Listed[]): Tree {
        const root: Node = {
            name: '',
            path: '',
            kind: 'directory',
            len: 0,
            children: new Map(),
        };
        for (const row of rows) {
            const path = normalise(row.path);
            if (path.length === 0) {
                continue;
            }
            const node = reach(root, path);
            node.kind = row.kind === 'directory' ? 'directory' : row.kind;
            node.len = row.kind === 'directory' ? 0 : row.len;
        }
        // A listed entry with something listed inside it is a nested archive,
        // and is presented as the directory it behaves like.
        mark(root);
        return new Tree(root);
    }

    /** The node at a path, or `undefined` when the archive holds none. */
    at(inside: string): Node | undefined {
        const path = normalise(inside);
        if (path.length === 0) {
            return this.root;
        }
        let node = this.root;
        for (const name of path.split('/')) {
            const child = node.children.get(name);
            if (!child) {
                return undefined;
            }
            node = child;
        }
        return node;
    }

    /** The children of a directory, in listing order. */
    childrenOf(inside: string): Node[] {
        const node = this.at(inside);
        return node ? [...node.children.values()] : [];
    }

    /** Every file in the archive, nested archives' contents included. */
    files(): Node[] {
        const found: Node[] = [];
        const walk = (node: Node): void => {
            for (const child of node.children.values()) {
                if (isDirectory(child)) {
                    walk(child);
                } else {
                    found.push(child);
                }
            }
        };
        walk(this.root);
        return found;
    }
}

/** The node at a path, creating whatever it hangs from. */
function reach(root: Node, path: string): Node {
    const { parent, name } = split(path);
    let node = root;
    if (parent.length > 0) {
        node = reach(root, parent);
    }
    const existing = node.children.get(name);
    if (existing) {
        return existing;
    }
    const made: Node = {
        name,
        path,
        kind: 'directory',
        len: 0,
        children: new Map(),
    };
    node.children.set(name, made);
    return made;
}

/** Turns every listed entry that holds entries into a nested archive. */
function mark(node: Node): void {
    for (const child of node.children.values()) {
        if (child.children.size > 0) {
            if (child.kind !== 'directory') {
                child.kind = 'archive';
            }
            mark(child);
        }
    }
}
