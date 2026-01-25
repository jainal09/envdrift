import * as vscode from 'vscode';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Agent status types
 */
export type AgentStatus = 'running' | 'stopped' | 'not_installed' | 'error';

/**
 * Agent status info
 */
export interface AgentStatusInfo {
    status: AgentStatus;
    version?: string;
    error?: string;
}

// Status check interval (30 seconds)
const CHECK_INTERVAL_MS = 30000;

// Callback for status changes
type StatusChangeCallback = (status: AgentStatusInfo) => void;

let statusCheckInterval: NodeJS.Timeout | undefined;
let currentStatus: AgentStatusInfo = { status: 'stopped' };
let onStatusChangeCallback: StatusChangeCallback | undefined;

/**
 * Check if the envdrift-agent binary is available
 */
async function isAgentInstalled(): Promise<boolean> {
    try {
        await execAsync('envdrift-agent --version');
        return true;
    } catch {
        return false;
    }
}

/**
 * Get the agent version
 */
async function getAgentVersion(): Promise<string | undefined> {
    try {
        const { stdout } = await execAsync('envdrift-agent --version');
        return stdout.trim();
    } catch {
        return undefined;
    }
}

/**
 * Check the current agent status
 */
export async function checkAgentStatus(): Promise<AgentStatusInfo> {
    try {
        // First check if agent is installed
        const installed = await isAgentInstalled();
        if (!installed) {
            return { status: 'not_installed' };
        }

        // Check agent status
        const { stdout } = await execAsync('envdrift-agent status');
        const output = stdout.toLowerCase();

        // Check for stopped/not running first to avoid false positives
        // (e.g., "not running" contains "running" as substring)
        if (output.includes('stopped') || output.includes('not running')) {
            const version = await getAgentVersion();
            return { status: 'stopped', version };
        } else if (/\brunning\b/.test(output)) {
            const version = await getAgentVersion();
            return { status: 'running', version };
        } else {
            return { status: 'stopped' };
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Check if it's a "not found" error
        if (errorMessage.includes('not found') || errorMessage.includes('ENOENT')) {
            return { status: 'not_installed' };
        }

        return { status: 'error', error: errorMessage };
    }
}

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
 * Update status and notify if changed
 */
async function updateStatus(): Promise<void> {
    const newStatus = await checkAgentStatus();

    // Check if status changed
    if (newStatus.status !== currentStatus.status) {
        currentStatus = newStatus;
        if (onStatusChangeCallback) {
            try {
                onStatusChangeCallback(newStatus);
            } catch {
                // Prevent unhandled exceptions from breaking the status check interval
            }
        }
    } else {
        currentStatus = newStatus;
    }
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
    try {
        // Add timeout to prevent hanging if agent doesn't respond
        await execAsync('envdrift-agent start', { timeout: 10000 });
        await refreshStatus();
        return currentStatus.status === 'running';
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Failed to start agent: ${errorMessage}`);
        return false;
    }
}

/**
 * Stop the agent
 */
export async function stopAgent(): Promise<boolean> {
    try {
        // Add timeout to prevent hanging if agent doesn't respond
        await execAsync('envdrift-agent stop', { timeout: 10000 });
        await refreshStatus();
        return currentStatus.status === 'stopped';
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`Failed to stop agent: ${errorMessage}`);
        return false;
    }
}

/**
 * Open installation instructions
 */
export function showInstallInstructions(): void {
    const message = 'EnvDrift Agent is not installed. Install it with: pip install envdrift && envdrift install agent';

    vscode.window.showInformationMessage(message, 'Copy Command', 'Learn More')
        .then(selection => {
            if (selection === 'Copy Command') {
                vscode.env.clipboard.writeText('pip install envdrift && envdrift install agent');
                vscode.window.showInformationMessage('Command copied to clipboard');
            } else if (selection === 'Learn More') {
                vscode.env.openExternal(vscode.Uri.parse('https://github.com/jainal09/envdrift#installation'));
            }
        });
}
