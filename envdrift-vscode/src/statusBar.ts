import * as vscode from 'vscode';
import { getConfig, setEnabled } from './config';
import { AgentStatusInfo, getCurrentStatus } from './agentStatus';

let statusBarItem: vscode.StatusBarItem;
let agentStatusBarItem: vscode.StatusBarItem;

/**
 * Create and show the status bar items
 */
export function createStatusBar(context: vscode.ExtensionContext): vscode.StatusBarItem {
    // Main EnvDrift status bar item (encryption toggle)
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.command = 'envdrift.toggleEnabled';
    context.subscriptions.push(statusBarItem);

    // Agent status bar item
    agentStatusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        99  // Slightly lower priority to appear to the right
    );
    agentStatusBarItem.command = 'envdrift.agentStatusClick';
    context.subscriptions.push(agentStatusBarItem);

    updateStatusBar();
    updateAgentStatusBar();

    statusBarItem.show();
    agentStatusBarItem.show();

    return statusBarItem;
}

/**
 * Update status bar based on current state
 */
export function updateStatusBar(message?: string): void {
    if (!statusBarItem) {
        return;
    }

    const config = getConfig();

    if (config.enabled) {
        statusBarItem.text = message || '$(lock) EnvDrift';
        statusBarItem.tooltip = 'EnvDrift: Auto-encryption enabled (click to disable)';
        statusBarItem.backgroundColor = undefined;
    } else {
        statusBarItem.text = '$(unlock) EnvDrift';
        statusBarItem.tooltip = 'EnvDrift: Auto-encryption disabled (click to enable)';
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }
}

/**
 * Update agent status bar based on current agent state
 */
export function updateAgentStatusBar(status?: AgentStatusInfo): void {
    if (!agentStatusBarItem) {
        return;
    }

    const agentStatus = status || getCurrentStatus();

    switch (agentStatus.status) {
        case 'running':
            agentStatusBarItem.text = '$(zap) Agent';
            agentStatusBarItem.tooltip = `EnvDrift Agent: Running${agentStatus.version ? ` (${agentStatus.version})` : ''}\nClick for options`;
            agentStatusBarItem.backgroundColor = undefined;
            agentStatusBarItem.color = new vscode.ThemeColor('terminal.ansiGreen');
            break;

        case 'stopped':
            agentStatusBarItem.text = '$(circle-slash) Agent';
            agentStatusBarItem.tooltip = 'EnvDrift Agent: Stopped\nClick to start';
            agentStatusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            agentStatusBarItem.color = undefined;
            break;

        case 'not_installed':
            agentStatusBarItem.text = '$(alert) Agent';
            agentStatusBarItem.tooltip = 'EnvDrift Agent: Not installed\nClick to install';
            agentStatusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            agentStatusBarItem.color = undefined;
            break;

        case 'error':
            agentStatusBarItem.text = '$(warning) Agent';
            agentStatusBarItem.tooltip = `EnvDrift Agent: Error\n${agentStatus.error || 'Unknown error'}\nClick for help`;
            agentStatusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            agentStatusBarItem.color = undefined;
            break;
    }
}

/**
 * Toggle enabled state
 */
export async function toggleEnabled(): Promise<void> {
    const config = getConfig();
    const newState = !config.enabled;

    await setEnabled(newState);
    updateStatusBar();

    vscode.window.showInformationMessage(
        `EnvDrift: Auto-encryption ${newState ? 'enabled' : 'disabled'}`
    );
}

/**
 * Show temporary status message
 */
export function showStatus(message: string, duration: number = 3000): void {
    if (statusBarItem) {
        statusBarItem.text = message;
        setTimeout(() => {
            updateStatusBar();
        }, duration);
    }
}

/**
 * Get the agent status bar item
 */
export function getAgentStatusBarItem(): vscode.StatusBarItem | undefined {
    return agentStatusBarItem;
}
