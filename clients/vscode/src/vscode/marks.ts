/**
 * What a buffered change looks like in the explorer.
 *
 * Apart from the provider that shows it because nothing here needs an editor.
 */

import type { Shown } from '../core/pending.js';

/** One badge, in the letters git uses for the same four things. */
export interface Mark {
    badge: string;
    tooltip: string;
    /** A colour id this extension contributes, defaulting to git's. */
    color: string;
}

const WAITING = 'not written to the archive yet';

/** How one buffered change is shown against the path it is visible at. */
export function markOf(one: Shown): Mark {
    switch (one.change.kind) {
        case 'write':
            return one.change.create
                ? { badge: 'A', tooltip: `Added, ${WAITING}`, color: 'rpf.addedResourceForeground' }
                : {
                      badge: 'M',
                      tooltip: `Modified, ${WAITING}`,
                      color: 'rpf.modifiedResourceForeground',
                  };
        case 'mkdir':
            return {
                badge: 'A',
                tooltip: `Added as a new folder, ${WAITING}`,
                color: 'rpf.addedResourceForeground',
            };
        case 'remove':
            return {
                badge: 'D',
                tooltip: `Deleted, ${WAITING}`,
                color: 'rpf.deletedResourceForeground',
            };
        case 'rename':
            return {
                badge: 'R',
                tooltip: `Renamed from ${one.held}, ${WAITING}`,
                color: 'rpf.renamedResourceForeground',
            };
    }
}
