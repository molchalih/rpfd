/**
 * Handing the editor the binary's own MCP server, so a user configures nothing.
 */

import * as vscode from 'vscode';

import { locate } from '../core/locate.js';
import { serversFor } from '../core/mcp.js';
import { note } from './messages.js';

/** The id the `contributes.mcpServerDefinitionProviders` entry declares. */
export const PROVIDER_ID = 'rpf.servers';

/** Registers the provider, and re-lists when the configured path changes. */
export function serveMcp(context: vscode.ExtensionContext): vscode.Disposable[] {
    const changed = new vscode.EventEmitter<void>();
    const provider: vscode.McpServerDefinitionProvider<vscode.McpStdioServerDefinition> = {
        onDidChangeMcpServerDefinitions: changed.event,
        provideMcpServerDefinitions: async () => {
            const found = await locate({
                setting: vscode.workspace.getConfiguration('rpf').get<string>('binaryPath'),
                extensionRoot: context.extensionPath,
                pathVariable: process.env.PATH,
            });
            if (!found.found) {
                note(`no MCP server is offered: ${found.instructions}`);
            }
            return serversFor(found).map(
                (server) =>
                    new vscode.McpStdioServerDefinition(
                        server.label,
                        server.command,
                        server.args,
                        {},
                        server.version,
                    ),
            );
        },
    };
    return [
        changed,
        vscode.workspace.onDidChangeConfiguration((event) => {
            if (event.affectsConfiguration('rpf.binaryPath')) {
                changed.fire();
            }
        }),
        vscode.lm.registerMcpServerDefinitionProvider(PROVIDER_ID, provider),
    ];
}
