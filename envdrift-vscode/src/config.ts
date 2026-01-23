import * as vscode from 'vscode';
// Re-export pure utilities for backwards compatibility
export { matchesPatterns, isExcluded } from './utils';

/**
 * Extension configuration interface
 */
export interface EnvDriftConfig {
    enabled: boolean;
    patterns: string[];
    exclude: string[];
    showNotifications: boolean;
}

/**
 * Get current extension configuration
 */
export function getConfig(): EnvDriftConfig {
    const config = vscode.workspace.getConfiguration('envdrift');
    return {
        enabled: config.get<boolean>('enabled', true),
        patterns: config.get<string[]>('patterns', ['.env*']),
        exclude: config.get<string[]>('exclude', ['.env.example', '.env.sample', '.env.keys']),
        showNotifications: config.get<boolean>('showNotifications', true),
    };
}

/**
 * Set enabled state
 */
export async function setEnabled(enabled: boolean): Promise<void> {
    const config = vscode.workspace.getConfiguration('envdrift');
    await config.update('enabled', enabled, vscode.ConfigurationTarget.Global);
}
