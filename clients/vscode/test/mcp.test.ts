import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import type { Located } from '../src/core/locate.js';
import { serversFor } from '../src/core/mcp.js';

describe('the server the editor is handed', () => {
    it('runs the binary that was located, as a stdio MCP server', () => {
        const found: Located = {
            found: true,
            path: '/opt/rpf',
            source: 'setting',
            version: 'rpf 0.0.0',
        };
        assert.deepEqual(serversFor(found), [
            { label: 'rpf', command: '/opt/rpf', args: ['serve', '--mcp'], version: 'rpf 0.0.0' },
        ]);
    });

    it('offers nothing at all when there is no binary to run', () => {
        const missing: Located = { found: false, tried: [], instructions: 'nowhere' };
        assert.deepEqual(serversFor(missing), []);
    });

    it('hands out its own argument array, so a resolve cannot edit the next one', () => {
        const found: Located = { found: true, path: '/opt/rpf', source: 'path', version: 'rpf 0.0.0' };
        const first = serversFor(found)[0];
        first?.args.push('--cache-dir');
        assert.deepEqual(serversFor(found)[0]?.args, ['serve', '--mcp']);
    });
});
