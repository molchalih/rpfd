/**
 * Packaging the extension as a `.vsix`. R8.3, the half that is ours.
 *
 * A `.vsix` is an Open Packaging Conventions zip: a content-type map, a
 * manifest, and the extension under `extension/`. Writing it here rather than
 * with the official packer is not asceticism — that tool **requires a publisher
 * id in `package.json`**, and a publisher id is an identity this repository
 * does not have and must not invent. Packaging and publishing are two acts, and
 * only the first one is ours: the id is supplied at packaging time by whoever
 * owns it, and without one this refuses to run rather than making one up.
 *
 * What ships is the explicit list in {@link contents} and nothing else. One
 * owner for "what is in the package" (`docs/conventions.md` §3); there is no
 * ignore file saying the same thing in the negative.
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

/** Where the extension is, relative to this file once it is compiled. */
const ROOT = path.resolve(__dirname, '../..');

/** One file in the package. */
interface Part {
    /** Its name inside the zip, always with `/`. */
    name: string;
    bytes: Buffer;
}

/** The extension's own manifest, as the repository holds it. */
interface Manifest {
    name: string;
    displayName: string;
    description: string;
    version: string;
    license?: string;
    keywords?: string[];
    categories?: string[];
    engines: { vscode: string };
    [key: string]: unknown;
}

/** Every file that goes into the package. */
export function contents(root: string, publisher: string): Part[] {
    const manifest = JSON.parse(
        fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
    ) as Manifest;
    const parts: Part[] = [];

    // The publisher is injected rather than committed: the repository's own
    // manifest carries no identity that is not its own.
    const shipped = { ...manifest, publisher };
    parts.push({
        name: 'extension/package.json',
        bytes: Buffer.from(`${JSON.stringify(shipped, null, 2)}\n`, 'utf8'),
    });

    for (const name of ['README.md', 'CHANGELOG.md']) {
        const at = path.join(root, name);
        if (fs.existsSync(at)) {
            parts.push({ name: `extension/${name}`, bytes: fs.readFileSync(at) });
        }
    }
    const license = licenseOf(root);
    if (license) {
        parts.push({ name: `extension/${license.name}`, bytes: fs.readFileSync(license.at) });
    }

    // The compiled extension, and nothing else out of dist: the tests and the
    // packaging script are not part of what is installed.
    for (const at of walk(path.join(root, 'dist', 'src'))) {
        if (!at.endsWith('.js')) {
            continue;
        }
        parts.push({
            name: `extension/${path.relative(root, at).split(path.sep).join('/')}`,
            bytes: fs.readFileSync(at),
        });
    }

    // A bundled binary, when one has been put there. R7.7: one static binary
    // per target, and the extension carries whichever the packager put in.
    for (const at of walk(path.join(root, 'bin'))) {
        parts.push({
            name: `extension/${path.relative(root, at).split(path.sep).join('/')}`,
            bytes: fs.readFileSync(at),
        });
    }

    parts.unshift(
        { name: '[Content_Types].xml', bytes: Buffer.from(contentTypes(parts), 'utf8') },
        { name: 'extension.vsixmanifest', bytes: Buffer.from(vsixManifest(shipped, publisher, root), 'utf8') },
    );
    return parts;
}

/**
 * The licence that goes in the package.
 *
 * It is the repository's, not the client directory's, so it is looked for in
 * both: one licence for the whole tree (`MIT OR Apache-2.0`), and a second copy
 * of it beside the extension would be a second owner of it.
 */
function licenseOf(root: string): { name: string; at: string } | undefined {
    for (const directory of [root, path.resolve(root, '..', '..')]) {
        for (const name of ['LICENSE-MIT', 'LICENSE-APACHE', 'LICENSE']) {
            const at = path.join(directory, name);
            if (fs.existsSync(at)) {
                return { name, at };
            }
        }
    }
    return undefined;
}

/** Every file under a directory, or nothing when there is no directory. */
function walk(at: string): string[] {
    if (!fs.existsSync(at)) {
        return [];
    }
    const found: string[] = [];
    for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
        const child = path.join(at, entry.name);
        if (entry.isDirectory()) {
            found.push(...walk(child));
        } else if (entry.isFile()) {
            found.push(child);
        }
    }
    return found.sort();
}

/** What each extension in the package is. Every part must be named here. */
function contentTypes(parts: readonly Part[]): string {
    const known: Record<string, string> = {
        json: 'application/json',
        vsixmanifest: 'text/xml',
        xml: 'text/xml',
        js: 'application/javascript',
        md: 'text/markdown',
        txt: 'text/plain',
    };
    const defaults = new Map<string, string>([['vsixmanifest', known.vsixmanifest ?? 'text/xml']]);
    const overrides: string[] = [];
    for (const part of parts) {
        const dot = path.basename(part.name).lastIndexOf('.');
        if (dot <= 0) {
            overrides.push(
                `  <Override PartName="/${escapeXml(part.name)}" ContentType="application/octet-stream"/>`,
            );
            continue;
        }
        const extension = part.name.slice(part.name.lastIndexOf('.') + 1).toLowerCase();
        defaults.set(extension, known[extension] ?? 'application/octet-stream');
    }
    const rows = [...defaults]
        .sort(([one], [two]) => one.localeCompare(two))
        .map(([extension, type]) => `  <Default Extension="${extension}" ContentType="${type}"/>`);
    return [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        ...rows,
        ...overrides,
        '</Types>',
        '',
    ].join('\n');
}

/** The gallery manifest, which is what an installer reads first. */
function vsixManifest(manifest: Manifest, publisher: string, root: string): string {
    const license = licenseOf(root)?.name;
    return [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">',
        '  <Metadata>',
        `    <Identity Language="en-US" Id="${escapeXml(manifest.name)}" Version="${escapeXml(manifest.version)}" Publisher="${escapeXml(publisher)}"/>`,
        `    <DisplayName>${escapeXml(manifest.displayName)}</DisplayName>`,
        `    <Description xml:space="preserve">${escapeXml(manifest.description)}</Description>`,
        `    <Tags>${escapeXml((manifest.keywords ?? []).join(','))}</Tags>`,
        `    <Categories>${escapeXml((manifest.categories ?? ['Other']).join(','))}</Categories>`,
        '    <GalleryFlags>Public</GalleryFlags>',
        '    <Properties>',
        `      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${escapeXml(manifest.engines.vscode)}"/>`,
        '      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value=""/>',
        '      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value=""/>',
        '      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace"/>',
        '    </Properties>',
        ...(license ? [`    <License>extension/${license}</License>`] : []),
        '  </Metadata>',
        '  <Installation>',
        '    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>',
        '  </Installation>',
        '  <Dependencies/>',
        '  <Assets>',
        '    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>',
        ...(fs.existsSync(path.join(root, 'README.md'))
            ? [
                  '    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>',
              ]
            : []),
        ...(license
            ? [
                  `    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/${license}" Addressable="true"/>`,
              ]
            : []),
        '  </Assets>',
        '</PackageManifest>',
        '',
    ].join('\n');
}

function escapeXml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/** Builds the package and returns where it was written. */
export function build(root: string, publisher: string, out?: string): string {
    const manifest = JSON.parse(
        fs.readFileSync(path.join(root, 'package.json'), 'utf8'),
    ) as Manifest;
    const at = out ?? path.join(root, `${manifest.name}-${manifest.version}.vsix`);
    fs.writeFileSync(at, zip(contents(root, publisher)));
    return at;
}

/** One zip file holding every part, each deflated. */
function zip(parts: readonly Part[]): Buffer {
    const locals: Buffer[] = [];
    const central: Buffer[] = [];
    let at = 0;
    for (const part of parts) {
        const name = Buffer.from(part.name, 'utf8');
        const deflated = zlib.deflateRawSync(part.bytes, { level: 9 });
        const crc = zlib.crc32(part.bytes);
        if (at + deflated.length > 0xffffffff) {
            throw new Error('the package is larger than a plain zip can address');
        }

        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4); // version needed
        local.writeUInt16LE(0x0800, 6); // names are UTF-8
        local.writeUInt16LE(8, 8); // deflated
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(deflated.length, 18);
        local.writeUInt32LE(part.bytes.length, 22);
        local.writeUInt16LE(name.length, 26);
        locals.push(local, name, deflated);

        const entry = Buffer.alloc(46);
        entry.writeUInt32LE(0x02014b50, 0);
        entry.writeUInt16LE(20, 4); // version made by
        entry.writeUInt16LE(20, 6); // version needed
        entry.writeUInt16LE(0x0800, 8);
        entry.writeUInt16LE(8, 10);
        entry.writeUInt32LE(crc, 16);
        entry.writeUInt32LE(deflated.length, 20);
        entry.writeUInt32LE(part.bytes.length, 24);
        entry.writeUInt16LE(name.length, 28);
        entry.writeUInt32LE(at, 42);
        central.push(entry, name);

        at += 30 + name.length + deflated.length;
    }

    const directory = Buffer.concat(central);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(parts.length, 8);
    end.writeUInt16LE(parts.length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(at, 16);
    return Buffer.concat([...locals, directory, end]);
}

/** What to say to somebody who has not named a publisher. */
export const NEEDS_PUBLISHER = [
    'A publisher id is needed, and this repository does not have one.',
    '',
    'A publisher id is an identity on a marketplace, and it belongs to whoever',
    'publishes — it is not a property of this source tree, and inventing one',
    'here would put somebody else\'s name on the package.',
    '',
    'Supply your own:',
    '  npm run package -- --publisher <your-publisher-id>',
    '  RPF_VSIX_PUBLISHER=<your-publisher-id> npm run package',
    '',
    'Publishing itself is a separate act and this script does not do it.',
].join('\n');

/** The command line. */
function main(argv: readonly string[]): number {
    const named = argv.indexOf('--publisher');
    const publisher = (named >= 0 ? argv[named + 1] : process.env.RPF_VSIX_PUBLISHER) ?? '';
    if (publisher.trim().length === 0) {
        process.stderr.write(`${NEEDS_PUBLISHER}\n`);
        return 2;
    }
    const outAt = argv.indexOf('--out');
    const out = outAt >= 0 ? argv[outAt + 1] : undefined;
    const written = build(ROOT, publisher.trim(), out);
    const parts = contents(ROOT, publisher.trim()).length;
    process.stdout.write(
        `${written}\n${parts} files, ${fs.statSync(written).size} bytes\n` +
            'Install it with: code --install-extension ' +
            `${written}\n`,
    );
    return 0;
}

if (require.main === module) {
    process.exitCode = main(process.argv.slice(2));
}
