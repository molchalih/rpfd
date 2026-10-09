import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { after, describe, it } from 'node:test';

import {
    TAG,
    addToProfile,
    install,
    installable,
    isNewer,
    layoutAt,
    layoutFor,
    onPath,
    profileFor,
    profileHolds,
    refresh,
    terminalPathFor,
    uninstall,
    userPathCommand,
} from '../src/core/command.js';
import type { Located, Source } from '../src/core/locate.js';
import { scratch } from './support.js';

const answers = (said: string | undefined) => (): Promise<string | undefined> => Promise.resolve(said);

const sha256 = (text: string): string => crypto.createHash('sha256').update(text).digest('hex');

const EXPORT_LINE = `export PATH="$HOME/.local/bin:$PATH"  ${TAG}`;

describe('the rpf command outside the extension', () => {
    const dir = scratch('command');
    let made = 0;

    after(() => {
        fs.rmSync(dir, { recursive: true, force: true });
    });

    /** A fresh directory holding a stand-in for the bundled binary. */
    function stage(bytes = 'rpf one'): { source: string; bin: string } {
        made += 1;
        const at = path.join(dir, String(made));
        fs.mkdirSync(at);
        const source = path.join(at, 'bundled');
        fs.writeFileSync(source, bytes, { mode: 0o755 });
        return { source, bin: path.join(at, 'bin') };
    }

    function marked(marker: string): { sha256: string[]; version: string } {
        return JSON.parse(fs.readFileSync(marker, 'utf8')) as { sha256: string[]; version: string };
    }

    it('goes to ~/.local/bin, or to its own folder under %LOCALAPPDATA%\\Programs', () => {
        const posix = layoutFor({ platform: 'linux', home: '/home/me', env: {} });
        assert.equal(posix.binary, '/home/me/.local/bin/rpf');
        assert.equal(posix.marker, '/home/me/.local/bin/.rpf-command.json');
        assert.equal(posix.owned, false, '~/.local/bin is shared with other commands');

        const windows = layoutFor({
            platform: 'win32',
            home: 'C:\\Users\\me',
            env: { LOCALAPPDATA: 'D:\\Local' },
        });
        assert.equal(windows.binary, 'D:\\Local\\Programs\\rpf\\rpf.exe');
        assert.equal(windows.owned, true);
        const fallback = layoutFor({ platform: 'win32', home: 'C:\\Users\\me', env: {} });
        assert.equal(fallback.binary, 'C:\\Users\\me\\AppData\\Local\\Programs\\rpf\\rpf.exe');
    });

    it('installs into an empty directory, executable, recording the digest and the version', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        assert.deepEqual(await install(source, '1.0.0', layout), { done: 'installed', at: layout.binary });
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'rpf one');
        if (process.platform !== 'win32') {
            assert.equal(fs.statSync(layout.binary).mode & 0o777, 0o755);
        }
        assert.deepEqual(marked(layout.marker), { sha256: [sha256('rpf one')], version: '1.0.0' });
        assert.deepEqual(fs.readdirSync(bin).sort(), ['.rpf-command.json', 'rpf'], 'a partial file was left');
        assert.deepEqual(await install(source, '1.0.0', layout), { done: 'unchanged', at: layout.binary });
    });

    it('refuses a file it did not put there, and says what that file is', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        fs.mkdirSync(bin);
        fs.writeFileSync(layout.binary, 'someone else');
        const outcome = await install(source, '1.0.0', layout, answers('rpf 0.1.0'));
        assert.deepEqual(outcome, { done: 'refused', at: layout.binary, holds: 'rpf 0.1.0' });
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'someone else');
        assert.ok(!fs.existsSync(layout.marker));

        const silent = await install(source, '1.0.0', layout, answers(undefined));
        assert.equal(silent.done === 'refused' && silent.holds, 'a file that does not answer --version as rpf');
    });

    it('refuses a file whose bytes changed since it was installed', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        fs.writeFileSync(layout.binary, 'edited by hand');
        assert.equal((await install(source, '1.0.0', layout, answers(undefined))).done, 'refused');
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'edited by hand');
    });

    it('never writes through a link, even one to identical bytes', { skip: process.platform === 'win32' }, async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        fs.rmSync(layout.binary);
        fs.symlinkSync(source, layout.binary);
        const outcome = await install(stage('rpf two').source, '1.0.0', layout, answers(undefined));
        assert.deepEqual(outcome, { done: 'refused', at: layout.binary, holds: `a link to ${source}` });
        assert.equal(fs.readFileSync(source, 'utf8'), 'rpf one');
    });

    it('refreshes its own unchanged copy from a newer version only, and never downgrades', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        assert.equal(await refresh(source, '2.0.0', layout), false, 'it installed where nothing was asked for');
        assert.ok(!fs.existsSync(layout.binary));

        await install(source, '1.1.0', layout);
        const older = stage('rpf older').source;
        assert.equal(await refresh(older, '1.0.0', layout), false, 'it downgraded');
        assert.equal(await refresh(older, '1.1.0', layout), false, 'a same-version editor replaced it');
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'rpf one');

        const newer = stage('rpf two').source;
        assert.equal(await refresh(newer, '1.2.0', layout), true);
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'rpf two');
        assert.deepEqual(marked(layout.marker), { sha256: [sha256('rpf two')], version: '1.2.0' });
        assert.deepEqual(fs.readdirSync(bin).sort(), ['.rpf-command.json', 'rpf'], 'a partial file was left');

        fs.writeFileSync(layout.binary, 'edited by hand');
        assert.equal(await refresh(source, '9.0.0', layout), false);
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'edited by hand');
    });

    it('records a newer version without rewriting identical bytes', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        assert.equal(await refresh(source, '1.0.1', layout), false);
        assert.equal(marked(layout.marker).version, '1.0.1');
    });

    it('replaces its own copy on an explicit install, whatever the version', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '2.0.0', layout);
        assert.equal((await install(stage('rpf two').source, '1.0.0', layout)).done, 'replaced');
        assert.equal(marked(layout.marker).version, '1.0.0');
    });

    it('keeps a copy ours when a replacement stopped between the rename and the record', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        // What the record says across the rename: the old digest, the new, the old version.
        const across = { sha256: [sha256('rpf one'), sha256('rpf two')], version: '1.0.0' };
        fs.writeFileSync(layout.marker, JSON.stringify(across));

        assert.deepEqual(await install(source, '1.0.0', layout), { done: 'unchanged', at: layout.binary });
        fs.writeFileSync(layout.binary, 'rpf two');
        const newer = stage('rpf two').source;
        assert.equal(await refresh(newer, '1.1.0', layout), false);
        assert.deepEqual(marked(layout.marker), { sha256: [sha256('rpf two')], version: '1.1.0' });

        fs.writeFileSync(layout.marker, JSON.stringify(across));
        fs.writeFileSync(layout.binary, 'rpf one');
        assert.deepEqual(await uninstall(layout), { done: 'removed', at: layout.binary });
    });

    it('treats a marker it cannot read as not ours', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        fs.writeFileSync(layout.marker, JSON.stringify({ sha256: sha256('rpf one') }));
        assert.equal((await install(source, '1.0.0', layout, answers(undefined))).done, 'refused');
    });

    it('uninstalls only its own copy', async () => {
        const { source, bin } = stage();
        const layout = layoutAt(bin, false);
        await install(source, '1.0.0', layout);
        fs.writeFileSync(path.join(bin, 'other-tool'), '');
        assert.deepEqual(await uninstall(layout), { done: 'removed', at: layout.binary });
        assert.deepEqual(fs.readdirSync(bin), ['other-tool'], 'it took more than its own two files');
        assert.deepEqual(await uninstall(layout), { done: 'absent', at: layout.binary });

        fs.writeFileSync(layout.binary, 'someone else');
        const outcome = await uninstall(layout, answers('rpf 0.1.0'));
        assert.deepEqual(outcome, { done: 'refused', at: layout.binary, holds: 'rpf 0.1.0' });
        assert.equal(fs.readFileSync(layout.binary, 'utf8'), 'someone else');
    });

    it('takes away a folder of its own once it is empty, and only then', async () => {
        const { source, bin } = stage();
        const owned = layoutAt(bin, true);
        await install(source, '1.0.0', owned);
        await uninstall(owned);
        assert.ok(!fs.existsSync(bin));

        await install(source, '1.0.0', owned);
        fs.writeFileSync(path.join(bin, 'notes.txt'), '');
        await uninstall(owned);
        assert.deepEqual(fs.readdirSync(bin), ['notes.txt']);
    });

    it('orders versions as semantic versions', () => {
        assert.ok(isNewer('1.10.0', '1.9.9'));
        assert.ok(isNewer('1.0.0', '1.0.0-rc.1'));
        assert.ok(isNewer('1.0.0-rc.10', '1.0.0-rc.9'));
        assert.ok(isNewer('1.0.0-rc.1.1', '1.0.0-rc.1'));
        assert.ok(isNewer('1.0.0-beta', '1.0.0-1'));
        assert.ok(!isNewer('1.0.0', '1.0.0'));
        assert.ok(!isNewer('1.0.0+build.2', '1.0.0+build.1'));
        assert.ok(!isNewer('0.9.0', '1.0.0'));
        assert.ok(!isNewer('2.0.0', 'not a version'), 'an unreadable record was replaced');
        assert.ok(!isNewer('', '1.0.0'));
    });

    it('picks the startup file of the shell, naming the folder the copy goes to', () => {
        const nothing = (): boolean => false;
        const of = (platform: NodeJS.Platform, env: Record<string, string>) =>
            profileFor({ platform, home: '/home/me', env }, nothing);
        assert.deepEqual(of('darwin', { SHELL: '/bin/zsh' }), { file: '/home/me/.zshrc', line: EXPORT_LINE });
        assert.equal(of('darwin', { SHELL: '/bin/zsh', ZDOTDIR: '/home/me/.zsh' })?.file, '/home/me/.zsh/.zshrc');
        assert.equal(of('linux', { SHELL: '/usr/bin/bash' })?.file, '/home/me/.bashrc');
        assert.equal(of('darwin', { SHELL: '/bin/bash' })?.file, '/home/me/.bash_profile');
        assert.deepEqual(of('linux', { SHELL: '/usr/bin/fish' }), {
            file: '/home/me/.config/fish/conf.d/rpf.fish',
            line: `fish_add_path --path "$HOME/.local/bin"  ${TAG}`,
        });
        assert.equal(of('linux', { SHELL: '/bin/tcsh' }), undefined);
        assert.equal(of('linux', {}), undefined);
        assert.equal(of('win32', { SHELL: '/bin/zsh' }), undefined);
    });

    it('does not hide ~/.profile behind a new ~/.bash_profile on macOS', () => {
        const only = (file: string) => (at: string): boolean => at === file;
        const host = { platform: 'darwin' as const, home: '/Users/me', env: { SHELL: '/bin/bash' } };
        assert.equal(profileFor(host, only('/Users/me/.profile'))?.file, '/Users/me/.profile');
        assert.equal(profileFor(host, (): boolean => true)?.file, '/Users/me/.bash_profile');
    });

    it('appends its line to a startup file once, whatever shell it is', async () => {
        const home = path.join(dir, 'home');
        for (const shell of ['zsh', 'bash', 'fish']) {
            const profile = profileFor(
                { platform: 'linux', home, env: { SHELL: `/bin/${shell}` } },
                () => false,
            );
            assert.ok(profile);
            if (shell === 'bash') {
                fs.mkdirSync(home, { recursive: true });
                fs.writeFileSync(profile.file, 'alias ll="ls -l"');
            }
            assert.equal(await profileHolds(profile), false);
            assert.equal(await addToProfile(profile), 'added');
            assert.equal(await addToProfile(profile), 'present');
            assert.equal(await profileHolds(profile), true);
            const lines = fs.readFileSync(profile.file, 'utf8').split('\n');
            assert.equal(lines.filter((line) => line === profile.line).length, 1, shell);
            if (shell === 'bash') {
                assert.deepEqual(lines, ['alias ll="ls -l"', EXPORT_LINE, '']);
            }
        }
    });

    it('reads a POSIX PATH', () => {
        const bin = '/home/me/.local/bin';
        assert.ok(onPath(bin, '/usr/bin:/home/me/.local/bin', 'linux'));
        assert.ok(onPath(bin, '/usr/bin:/home/me/.local/bin/', 'linux'));
        assert.ok(onPath(bin, '/usr/bin:~/.local/bin', 'linux', '/home/me'));
        assert.ok(!onPath(bin, '/usr/bin:/home/me/.local/bin2', 'linux'));
        assert.ok(!onPath(bin, '/usr/bin:/Home/me/.local/bin', 'linux'), 'POSIX paths are case-sensitive');
        assert.ok(!onPath(bin, undefined, 'linux'));
        assert.ok(!onPath(bin, '', 'linux'));
    });

    it('reads a Windows PATH', () => {
        const bin = 'C:\\Users\\me\\AppData\\Local\\Programs\\rpf';
        assert.ok(onPath(bin, 'C:\\Windows;c:\\users\\ME\\appdata\\local\\programs\\RPF\\', 'win32'));
        assert.ok(onPath(bin, 'C:\\Windows;"C:\\Users\\me\\AppData\\Local\\Programs\\rpf"', 'win32'));
        assert.ok(onPath(bin, ';;C:/Users/me/AppData/Local/Programs/rpf;', 'win32'));
        assert.ok(!onPath(bin, 'C:\\Windows;C:\\Users\\me\\AppData\\Local\\Programs', 'win32'));
        assert.ok(!onPath(bin, 'C:\\Users\\me\\AppData\\Local\\Programs\\rpf', 'linux'), 'split on the wrong separator');
    });

    it('adds to the user PATH only, through the registry rather than setx', () => {
        const script = (directory: string): string => {
            const run = userPathCommand(directory);
            assert.equal(run.command, 'powershell.exe');
            const encoded = run.args[run.args.indexOf('-EncodedCommand') + 1] ?? '';
            return Buffer.from(encoded, 'base64').toString('utf16le');
        };
        const plain = script("C:\\Users\\o'brien\\AppData\\Local\\Programs\\rpf");
        assert.match(plain, /\$dir = 'C:\\Users\\o''brien\\AppData\\Local\\Programs\\rpf'/);
        assert.match(plain, /CurrentUser/);
        assert.match(plain, /DoNotExpandEnvironmentNames/);
        assert.match(plain, /ExpandEnvironmentVariables\(\$_/, 'an unexpanded entry for the folder is not seen');
        assert.match(plain, /SetEnvironmentVariable\('RPF_PATH_CHANGED', \$null, 'User'\)/);
        assert.doesNotMatch(plain, /Machine|LocalMachine|setx/i);

        // PowerShell closes a single-quoted string at any of U+2018 to U+201B too.
        const curly = script('C:\\Users\\o\u2019brien\u2018\u201A\u201B\\rpf');
        assert.ok(curly.includes("$dir = 'C:\\Users\\o\u2019\u2019brien\u2018\u2018\u201A\u201A\u201B\u201B\\rpf'"));
    });

    describe('the terminals', () => {
        const found = (source: Source, at = '/ext/bin/darwin-arm64/rpf'): Located => ({
            found: true,
            path: at,
            source,
            version: 'rpf 0.0.0',
        });
        const none = (): boolean => false;

        it("get the bundled binary's own folder first on PATH", () => {
            assert.equal(terminalPathFor(found('bundled'), '/usr/bin', 'darwin', none), '/ext/bin/darwin-arm64:');
            assert.equal(
                terminalPathFor(found('bundled', 'C:\\ext\\bin\\win32-x64\\rpf.exe'), 'C:\\Windows', 'win32', none),
                'C:\\ext\\bin\\win32-x64;',
            );
        });

        it('get nothing for a configured binary or one found on PATH, whose folder is shared', () => {
            assert.equal(terminalPathFor(found('setting', '/opt/homebrew/bin/rpf'), '/usr/bin', 'darwin', none), undefined);
            assert.equal(terminalPathFor(found('path', '/opt/homebrew/bin/rpf'), '/opt/homebrew/bin', 'darwin', none), undefined);
            assert.equal(terminalPathFor({ found: false, tried: [], instructions: '' }, '/usr/bin', 'darwin', none), undefined);
        });

        it('get nothing when an rpf on PATH would answer, so the user\'s own is not shadowed', () => {
            const at = (file: string) => (candidate: string): boolean => candidate === file;
            const pathVariable = '/usr/bin:/home/me/.local/bin';
            assert.equal(terminalPathFor(found('bundled'), pathVariable, 'darwin', at('/home/me/.local/bin/rpf')), undefined);
            assert.equal(terminalPathFor(found('bundled'), pathVariable, 'darwin', at('/elsewhere/rpf')), '/ext/bin/darwin-arm64:');
        });
    });

    it('copies a configured or bundled binary, never one found on PATH', () => {
        const of = (source: Source): Located => ({ found: true, path: `/${source}/rpf`, source, version: 'rpf 0.0.0' });
        assert.equal(installable(of('bundled')), '/bundled/rpf');
        assert.equal(installable(of('setting')), '/setting/rpf');
        assert.equal(installable(of('path')), undefined, 'a second copy of a command already on PATH');
        assert.equal(installable({ found: false, tried: [], instructions: '' }), undefined);
    });
});
