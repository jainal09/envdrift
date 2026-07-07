import * as vscode from 'vscode';
import {
    AgentStatusInfo,
    checkAgentStatus,
    startAgentCore,
    stopAgentCore,
} from './agentCore';

export { AgentStatus, AgentStatusInfo, checkAgentStatus } from './agentCore';

// Status check interval (30 seconds)
const CHECK_INTERVAL_MS = 30000;

// Callback for status changes
type StatusChangeCallback = (status: AgentStatusInfo) => void;

let statusCheckInterval: NodeJS.Timeout | undefined;
let currentStatus: AgentStatusInfo = { status: 'stopped' };
let onStatusChangeCallback: StatusChangeCallback | undefined;

/**
 * Start periodic status checking
 */
export function startStatusChecking(onChange?: StatusChangeCallback): void {
    onStatusChangeCallback = onChange;

    // Initial check
    updateStatus();

    // Set up interval
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
    }
    statusCheckInterval = setInterval(updateStatus, CHECK_INTERVAL_MS);
}

/**
 * Stop periodic status checking
 */
export function stopStatusChecking(): void {
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
        statusCheckInterval = undefined;
    }
}

/**
 * Cache a freshly observed status and notify if it changed
 */
function applyStatus(newStatus: AgentStatusInfo): void {
    const changed = newStatus.status !== currentStatus.status;
    currentStatus = newStatus;
    if (changed && onStatusChangeCallback) {
        try {
            onStatusChangeCallback(newStatus);
        } catch {
            // Prevent unhandled exceptions from breaking the status check interval
        }
    }
}

/**
 * Update status and notify if changed
 */
async function updateStatus(): Promise<void> {
    applyStatus(await checkAgentStatus());
}

/**
 * Get current cached status
 */
export function getCurrentStatus(): AgentStatusInfo {
    return currentStatus;
}

/**
 * Force a status refresh
 */
export async function refreshStatus(): Promise<AgentStatusInfo> {
    await updateStatus();
    return currentStatus;
}

/**
 * Start the agent
 */
export async function startAgent(): Promise<boolean> {
    const result = await startAgentCore();
    // The core already verified the post-action status; reuse it instead of
    // spawning another check.
    applyStatus(result.status);
    if (!result.ok) {
        vscode.window.showErrorMessage(`Failed to start agent: ${result.error ?? 'unknown error'}`);
    }
    return result.ok;
}

/**
 * Stop the agent
 */
export async function stopAgent(): Promise<boolean> {
    const result = await stopAgentCore();
    // The core already verified the post-action status; reuse it instead of
    // spawning another check.
    applyStatus(result.status);
    if (!result.ok) {
        vscode.window.showErrorMessage(`Failed to stop agent: ${result.error ?? 'unknown error'}`);
    }
    return result.ok;
}

/**
 * Open installation instructions
 */
export function showInstallInstructions(): void {
    const installCmd = process.platform === 'win32'
        ? 'irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex'
        : 'curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh';
    const message = `EnvDrift Agent is not installed. Install it with: ${installCmd}`;

    vscode.window.showInformationMessage(message, 'Copy Command', 'Learn More')
        .then(selection => {
            if (selection === 'Copy Command') {
                vscode.env.clipboard.writeText(installCmd);
                vscode.window.showInformationMessage('Command copied to clipboard');
            } else if (selection === 'Learn More') {
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/jainal09/envdrift#installation'));
            }
        });
}
