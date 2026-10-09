import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { labelOf } from '../src/core/label.js';

describe('the name an archive is shown by', () => {
    it('is its file name and the folder holding it', () => {
        assert.equal(labelOf('/mods/dlcpacks/mpheist/dlc.rpf'), 'dlc.rpf — mpheist');
    });

    it('tells apart two archives with one name in two folders', () => {
        const one = labelOf('/mods/dlcpacks/mpheist/dlc.rpf');
        const other = labelOf('/mods/dlcpacks/mpbeach/dlc.rpf');
        assert.notEqual(one, other);
        assert.equal(other, 'dlc.rpf — mpbeach');
    });

    it('reads either separator, as a Windows path holds them', () => {
        assert.equal(labelOf('C:\\Games\\mods\\mpheist\\dlc.rpf'), 'dlc.rpf — mpheist');
        assert.equal(labelOf('\\\\?\\C:\\Games\\mpheist\\dlc.rpf'), 'dlc.rpf — mpheist');
        assert.equal(labelOf('C:/Games/mpheist/dlc.rpf'), 'dlc.rpf — mpheist');
    });

    it('reads past a trailing or doubled separator', () => {
        assert.equal(labelOf('/mods/mpheist/dlc.rpf/'), 'dlc.rpf — mpheist');
        assert.equal(labelOf('/mods/mpheist//dlc.rpf'), 'dlc.rpf — mpheist');
        assert.equal(labelOf('C:\\mods\\mpheist\\\\dlc.rpf\\'), 'dlc.rpf — mpheist');
    });

    it('is labelled with the share for an archive at a network share root', () => {
        assert.equal(labelOf('\\\\server\\mods\\dlc.rpf'), 'dlc.rpf — mods');
    });

    it('is the bare file name for an archive at a filesystem root', () => {
        assert.equal(labelOf('/dlc.rpf'), 'dlc.rpf');
        assert.equal(labelOf('C:\\dlc.rpf'), 'dlc.rpf');
        assert.equal(labelOf('\\\\?\\D:\\dlc.rpf'), 'dlc.rpf');
        assert.equal(labelOf('dlc.rpf'), 'dlc.rpf');
    });
});
