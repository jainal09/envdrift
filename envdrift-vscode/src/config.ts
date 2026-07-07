import * as vscode from 'vscode';
import { pickConfigTargetScope } from './utils';
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
 * Set enabled state, writing to the scope that currently defines the value so
 * the toggle actually takes effect (a workspace-level `envdrift.enabled` would
 * otherwise shadow a global write forever).
 */
export async function setEnabled(enabled: boolean): Promise<void> {
    const config = vscode.workspace.getConfiguration('envdrift');
    const scope = pickConfigTargetScope(config.inspect<boolean>('enabled'));
    const target =
        scope === 'workspaceFolder'
            ? vscode.ConfigurationTarget.WorkspaceFolder
            : scope === 'workspace'
                ? vscode.ConfigurationTarget.Workspace
                : vscode.ConfigurationTarget.Global;
    await config.update('enabled', enabled, target);
}
