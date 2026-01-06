import * as vscode from 'vscode';
import { createStatusBar, toggleEnabled, updateStatusBar } from './statusBar';
import { startWatching, encryptCurrentFile } from './fileWatcher';
import { getConfig, setEnabled } from './config';

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('EnvDrift extension is now active');

    // Create status bar
    createStatusBar(context);

    // Start file watching
    startWatching(context);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.enable', async () => {
            await setEnabled(true);
            updateStatusBar();
            vscode.window.showInformationMessage('EnvDrift: Auto-encryption enabled');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.disable', async () => {
            await setEnabled(false);
            updateStatusBar();
            vscode.window.showInformationMessage('EnvDrift: Auto-encryption disabled');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.toggleEnabled', toggleEnabled)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.encryptNow', encryptCurrentFile)
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.showStatus', () => {
            const config = getConfig();
            const status = config.enabled ? 'enabled' : 'disabled';
            vscode.window.showInformationMessage(
                `EnvDrift Status: Auto-encryption is ${status}\n` +
                `Patterns: ${config.patterns.join(', ')}\n` +
                `Excluded: ${config.exclude.join(', ')}`
            );
        })
    );

    // Listen for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration((e) => {
            if (e.affectsConfiguration('envdrift')) {
                updateStatusBar();
            }
        })
    );
}

/**
 * Extension deactivation
 */
export function deactivate() {
    console.log('EnvDrift extension is now deactivated');
}
