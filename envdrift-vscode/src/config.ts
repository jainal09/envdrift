import * as vscode from 'vscode';

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
 * Check if a file matches our watched patterns
 */
export function matchesPatterns(fileName: string, patterns: string[]): boolean {
    const baseName = fileName.split('/').pop() || fileName;
    return patterns.some(pattern => {
        // Escape regex special chars except *, then convert * to .*
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$');
        return regex.test(baseName);
    });
}

/**
 * Check if a file should be excluded
 */
export function isExcluded(fileName: string, exclude: string[]): boolean {
    const baseName = fileName.split('/').pop() || fileName;
    return exclude.includes(baseName);
}

/**
 * Set enabled state
 */
export async function setEnabled(enabled: boolean): Promise<void> {
    const config = vscode.workspace.getConfiguration('envdrift');
    await config.update('enabled', enabled, vscode.ConfigurationTarget.Global);
}
