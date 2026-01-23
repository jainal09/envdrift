import * as vscode from 'vscode';
import { createStatusBar, toggleEnabled, updateStatusBar, updateAgentStatusBar } from './statusBar';
import { startWatching, encryptCurrentFile } from './fileWatcher';
import { getConfig, setEnabled } from './config';
import {
    startStatusChecking,
    stopStatusChecking,
    getCurrentStatus,
    refreshStatus,
    startAgent,
    stopAgent,
    showInstallInstructions,
    AgentStatusInfo
} from './agentStatus';

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('EnvDrift extension is now active');

    // Create status bar
    createStatusBar(context);

    // Start file watching
    startWatching(context);

    // Start agent status checking
    startStatusChecking((status: AgentStatusInfo) => {
        updateAgentStatusBar(status);
    });

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
            const agentStatus = getCurrentStatus();
            const encryptionStatus = config.enabled ? 'enabled' : 'disabled';
            const agentStatusText = getAgentStatusText(agentStatus);

            vscode.window.showInformationMessage(
                `EnvDrift Status:\n` +
                `Auto-encryption: ${encryptionStatus}\n` +
                `Agent: ${agentStatusText}\n` +
                `Patterns: ${config.patterns.join(', ')}\n` +
                `Excluded: ${config.exclude.join(', ')}`
            );
        })
    );

    // Agent status click command - shows context menu
    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.agentStatusClick', async () => {
            const status = getCurrentStatus();

            switch (status.status) {
                case 'running':
                    // Show options menu for running agent
                    const runningChoice = await vscode.window.showQuickPick(
                        [
                            { label: '$(info) Show Agent Info', action: 'info' },
                            { label: '$(debug-stop) Stop Agent', action: 'stop' },
                            { label: '$(sync) Refresh Status', action: 'refresh' }
                        ],
                        { placeHolder: 'EnvDrift Agent is running' }
                    );

                    if (runningChoice) {
                        switch (runningChoice.action) {
                            case 'info':
                                vscode.window.showInformationMessage(
                                    `EnvDrift Agent is running${status.version ? ` (version: ${status.version})` : ''}`
                                );
                                break;
                            case 'stop':
                                const stopped = await stopAgent();
                                if (stopped) {
                                    vscode.window.showInformationMessage('EnvDrift Agent stopped');
                                }
                                updateAgentStatusBar();
                                break;
                            case 'refresh':
                                await refreshStatus();
                                updateAgentStatusBar();
                                break;
                        }
                    }
                    break;

                case 'stopped':
                    // Offer to start the agent
                    const startChoice = await vscode.window.showQuickPick(
                        [
                            { label: '$(play) Start Agent', action: 'start' },
                            { label: '$(sync) Refresh Status', action: 'refresh' }
                        ],
                        { placeHolder: 'EnvDrift Agent is stopped' }
                    );

                    if (startChoice) {
                        switch (startChoice.action) {
                            case 'start':
                                const started = await startAgent();
                                if (started) {
                                    vscode.window.showInformationMessage('EnvDrift Agent started');
                                }
                                updateAgentStatusBar();
                                break;
                            case 'refresh':
                                await refreshStatus();
                                updateAgentStatusBar();
                                break;
                        }
                    }
                    break;

                case 'not_installed':
                    // Show installation instructions
                    showInstallInstructions();
                    break;

                case 'error':
                    // Show error and offer to refresh
                    const errorChoice = await vscode.window.showQuickPick(
                        [
                            { label: '$(sync) Refresh Status', action: 'refresh' },
                            { label: '$(link-external) Get Help', action: 'help' }
                        ],
                        { placeHolder: `Agent Error: ${status.error || 'Unknown error'}` }
                    );

                    if (errorChoice) {
                        switch (errorChoice.action) {
                            case 'refresh':
                                await refreshStatus();
                                updateAgentStatusBar();
                                break;
                            case 'help':
                                vscode.env.openExternal(
                                    vscode.Uri.parse('https://github.com/jainal09/envdrift/issues')
                                );
                                break;
                        }
                    }
                    break;
            }
        })
    );

    // Start agent command
    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.startAgent', async () => {
            const status = getCurrentStatus();
            if (status.status === 'not_installed') {
                showInstallInstructions();
                return;
            }

            const started = await startAgent();
            if (started) {
                vscode.window.showInformationMessage('EnvDrift Agent started');
            }
            updateAgentStatusBar();
        })
    );

    // Stop agent command
    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.stopAgent', async () => {
            const stopped = await stopAgent();
            if (stopped) {
                vscode.window.showInformationMessage('EnvDrift Agent stopped');
            }
            updateAgentStatusBar();
        })
    );

    // Refresh agent status command
    context.subscriptions.push(
        vscode.commands.registerCommand('envdrift.refreshAgentStatus', async () => {
            await refreshStatus();
            updateAgentStatusBar();
            vscode.window.showInformationMessage('Agent status refreshed');
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
 * Get human-readable agent status text
 */
function getAgentStatusText(status: AgentStatusInfo): string {
    switch (status.status) {
        case 'running':
            return `Running${status.version ? ` (${status.version})` : ''}`;
        case 'stopped':
            return 'Stopped';
        case 'not_installed':
            return 'Not installed';
        case 'error':
            return `Error: ${status.error || 'Unknown'}`;
        default:
            return 'Unknown';
    }
}

/**
 * Extension deactivation
 */
export function deactivate() {
    console.log('EnvDrift extension is now deactivated');
    stopStatusChecking();
}
