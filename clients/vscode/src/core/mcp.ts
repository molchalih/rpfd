/**
 * What the editor is told about `rpf serve --mcp`.
 *
 * An agent inside the editor cannot see a mounted `rpf:` folder — the scheme
 * exists only to the editor's own file service — so what it is handed instead
 * is the MCP server the binary already carries. `clients/mcp/README.md` is the
 * authority on that server's shape.
 */

import type { Located } from './locate.js';

/** One stdio server, in the terms the editor's own definition takes. */
export interface Server {
    label: string;
    command: string;
    args: string[];
    /** The binary's `--version` line, so a changed binary re-lists its tools. */
    version: string;
}

/** How the binary is run as a server. */
export const SERVE_MCP = ['serve', '--mcp'];

/**
 * The servers to advertise for what {@link locate} found.
 *
 * Nothing at all when there is no binary: a server the editor cannot start is
 * worse than one it was never offered.
 */
export function serversFor(found: Located): Server[] {
    if (!found.found) {
        return [];
    }
    return [
        {
            label: 'rpf',
            command: found.path,
            args: [...SERVE_MCP],
            version: found.version,
        },
    ];
}
