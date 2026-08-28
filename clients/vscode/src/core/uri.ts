/**
 * How an entry inside an archive is addressed as a URI. R7.1.
 *
 * `rpf://<token>/<path inside the archive>?<the archive's own path>`
 *
 * Two things have to be in one URI — which archive, and which entry inside it —
 * and the entry has to be the *tail* of the path, because that is what an
 * editor joins a child name onto and splits a parent off. So the archive goes
 * in the query, where it is one opaque string with no separator to be confused
 * with the path's.
 *
 * The authority is a digest of the query rather than the archive's path spelt
 * out: an authority is compared case-insensitively by convention, and archive
 * paths are not. It carries no information of its own — it is checked against
 * the query, and a URI whose two halves disagree is refused rather than
 * resolved to one of them.
 *
 * `/` is the only separator inside an archive, on every platform, and `\` is an
 * ordinary character in an entry name — DR-016. So nothing here treats a
 * backslash as a separator, and a name holding one survives the round trip.
 */

import { createHash } from 'node:crypto';

/** The scheme this client serves. */
export const SCHEME = 'rpf';

/** How much of the digest names an archive. */
const TOKEN_LENGTH = 16;

/** The parts of a URI, each held decoded. */
export interface UriParts {
    scheme: string;
    authority: string;
    path: string;
    query: string;
}

/** Which archive, and which entry inside it. */
export interface Address {
    /** The archive's path on the daemon's filesystem. DR-014. */
    archive: string;
    /** The path inside the archive; empty for its root. */
    inside: string;
}

/** Raised for a URI this client cannot address an entry with. */
export class BadUri extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'BadUri';
    }
}

/** The authority naming one archive. */
export function tokenFor(archive: string): string {
    return createHash('sha256').update(archive, 'utf8').digest('hex').slice(0, TOKEN_LENGTH);
}

/** The URI of one entry, or of the archive's root when `inside` is empty. */
export function uriOf(address: Address): UriParts {
    const inside = normalise(address.inside);
    return {
        scheme: SCHEME,
        authority: tokenFor(address.archive),
        path: `/${inside}`,
        query: address.archive,
    };
}

/** The URI of an archive's root, which is what a workspace folder holds. */
export function rootOf(archive: string): UriParts {
    return uriOf({ archive, inside: '' });
}

/**
 * Which archive and which entry a URI names.
 *
 * @throws {BadUri} when the scheme is not this one, when the archive is
 * missing, when the authority does not match it, or when the path inside
 * climbs out of the archive.
 */
export function addressOf(uri: UriParts): Address {
    if (uri.scheme !== SCHEME) {
        throw new BadUri(`${uri.scheme}: is not the ${SCHEME}: scheme`);
    }
    const archive = uri.query;
    if (archive.length === 0) {
        throw new BadUri('the URI names no archive: its query is where the archive path goes');
    }
    if (uri.authority !== tokenFor(archive)) {
        throw new BadUri(
            `the URI's authority ${uri.authority} does not name the archive ${archive}`,
        );
    }
    return { archive, inside: normalise(uri.path) };
}

/**
 * A path inside an archive, as the daemon takes one: no leading separator, no
 * empty component, and nothing that climbs.
 *
 * The climbing rules are DR-013's tree rules, asked here so a URI that cannot
 * name an entry is refused where the user can still see which one they meant.
 * The daemon asks them again, and it is the daemon's answer that decides.
 *
 * @throws {BadUri} for a component that is empty, `.` or `..`.
 */
export function normalise(inside: string): string {
    const trimmed = inside.replace(/^\/+/, '').replace(/\/+$/, '');
    if (trimmed.length === 0) {
        return '';
    }
    const components = trimmed.split('/');
    for (const component of components) {
        if (component.length === 0) {
            throw new BadUri(`${inside} has an empty component`);
        }
        if (component === '.' || component === '..') {
            throw new BadUri(`${inside} has a ${component} component, which names no entry`);
        }
    }
    return components.join('/');
}

/** The path of a child of `inside`. */
export function join(inside: string, name: string): string {
    const parent = normalise(inside);
    return parent.length === 0 ? normalise(name) : `${parent}/${normalise(name)}`;
}

/** The directory holding `inside`, and the name within it. */
export function split(inside: string): { parent: string; name: string } {
    const whole = normalise(inside);
    const cut = whole.lastIndexOf('/');
    return cut < 0
        ? { parent: '', name: whole }
        : { parent: whole.slice(0, cut), name: whole.slice(cut + 1) };
}
