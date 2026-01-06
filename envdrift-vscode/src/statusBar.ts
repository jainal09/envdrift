import * as vscode from 'vscode';
import { getConfig, setEnabled } from './config';

let statusBarItem: vscode.StatusBarItem;

/**
 * Create and show the status bar item
 */
export function createStatusBar(context: vscode.ExtensionContext): vscode.StatusBarItem {
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Right,
        100
    );
    statusBarItem.command = 'envdrift.toggleEnabled';
    context.subscriptions.push(statusBarItem);

    updateStatusBar();
    statusBarItem.show();

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
    const originalText = statusBarItem?.text;

    if (statusBarItem) {
        statusBarItem.text = message;
        setTimeout(() => {
            updateStatusBar();
        }, duration);
    }
}
