import * as vscode from 'vscode';

/**
 * The "EnvDrift" output channel (View > Output > EnvDrift).
 *
 * The troubleshooting guide pointed users at this channel while the extension
 * never created one, leaving failures unobservable when notifications were
 * disabled (#482). Encryption attempts and CLI errors are logged here.
 */
let channel: vscode.OutputChannel | undefined;
let disposed = false;

/**
 * Get (lazily creating) the EnvDrift output channel. Activation calls this,
 * which also revives the logger after a previous deactivation.
 */
export function getOutputChannel(): vscode.OutputChannel {
    disposed = false;
    if (!channel) {
        channel = vscode.window.createOutputChannel('EnvDrift');
    }
    return channel;
}

/**
 * Append a timestamped line to the EnvDrift output channel.
 *
 * After deactivation this is a no-op: in-flight async work must not
 * silently re-create a channel that nothing would ever dispose.
 */
export function log(message: string): void {
    if (disposed) {
        return;
    }
    getOutputChannel().appendLine(`[${new Date().toISOString()}] ${message}`);
}

/**
 * Reveal the EnvDrift output channel (no-op after deactivation).
 */
export function showLogs(): void {
    if (disposed) {
        return;
    }
    getOutputChannel().show(true);
}

/**
 * Dispose the channel (extension deactivation).
 */
export function disposeLogger(): void {
    disposed = true;
    if (channel) {
        channel.dispose();
        channel = undefined;
    }
}
