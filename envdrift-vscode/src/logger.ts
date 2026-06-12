import * as vscode from 'vscode';

/**
 * The "EnvDrift" output channel (View > Output > EnvDrift).
 *
 * The troubleshooting guide pointed users at this channel while the extension
 * never created one, leaving failures unobservable when notifications were
 * disabled (#482). Encryption attempts and CLI errors are logged here.
 */
let channel: vscode.OutputChannel | undefined;

/**
 * Get (lazily creating) the EnvDrift output channel.
 */
export function getOutputChannel(): vscode.OutputChannel {
    if (!channel) {
        channel = vscode.window.createOutputChannel('EnvDrift');
    }
    return channel;
}

/**
 * Append a timestamped line to the EnvDrift output channel.
 */
export function log(message: string): void {
    getOutputChannel().appendLine(`[${new Date().toISOString()}] ${message}`);
}

/**
 * Reveal the EnvDrift output channel.
 */
export function showLogs(): void {
    getOutputChannel().show(true);
}

/**
 * Dispose the channel (extension deactivation).
 */
export function disposeLogger(): void {
    if (channel) {
        channel.dispose();
        channel = undefined;
    }
}
