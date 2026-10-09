/**
 * How an archive is named to a person: `dlc.rpf — mpheist`, its file name and
 * the folder holding it, so that two archives with one name are two labels.
 */

/** A Windows drive, which is a filesystem root rather than a folder's name. */
const DRIVE = /^[A-Za-z]:$/;

/**
 * The archive's file name and its parent folder's, whichever separator the
 * path uses. An archive at `/` or at a drive's root has no folder, and is its
 * name; one at a network share's root is labelled with the share.
 */
export function labelOf(archive: string): string {
    const components = archive.split(/[\\/]/).filter((component) => component.length > 0);
    const name = components.pop() ?? archive;
    const parent = components.pop();
    return parent === undefined || DRIVE.test(parent) ? name : `${name} — ${parent}`;
}
