/**
 * Run by the editor with plain `node` once the extension is uninstalled: takes
 * away the `rpf` command it installed, and nothing it did not.
 */

import { currentHost, layoutFor, uninstall } from './core/command.js';

uninstall(layoutFor(currentHost()), () => Promise.resolve(undefined)).then(
    (outcome) => console.log(`rpf: ${outcome.done} ${outcome.at}`),
    (failure: unknown) => {
        console.error(`rpf: ${String(failure)}`);
        process.exitCode = 1;
    },
);
