import * as vscode from 'vscode';
import * as path from 'path';
import { getConfig, matchesPatterns, isExcluded } from './config';
import { encryptFile, isEncrypted } from './encryption';
import { showStatus } from './statusBar';

let disposable: vscode.Disposable | undefined;

/**
 * Start watching for file close events
 */
export function startWatching(context: vscode.ExtensionContext): void {
    disposable = vscode.workspace.onDidCloseTextDocument(async (document) => {
        await handleDocumentClose(document);
    });
    context.subscriptions.push(disposable);
}

/**
 * Handle document close event
 */
async function handleDocumentClose(document: vscode.TextDocument): Promise<void> {
    const config = getConfig();

    // Check if enabled
    if (!config.enabled) {
        return;
    }

    // Only handle file scheme
    if (document.uri.scheme !== 'file') {
        return;
    }

    const filePath = document.uri.fsPath;
    const fileName = path.basename(filePath);

    // Check if file matches patterns
    if (!matchesPatterns(fileName, config.patterns)) {
        return;
    }

    // Check if file is excluded
    if (isExcluded(fileName, config.exclude)) {
        return;
    }

    // Check if already encrypted
    if (await isEncrypted(filePath)) {
        return;
    }

    // Encrypt the file
    showStatus('$(sync~spin) Encrypting...', 10000);

    const result = await encryptFile(filePath);

    if (result.success) {
        showStatus('$(check) Encrypted', 3000);
        if (config.showNotifications) {
            vscode.window.showInformationMessage(`🔐 ${result.message}`);
        }
    } else {
        showStatus('$(error) Failed', 3000);
        if (config.showNotifications) {
            vscode.window.showWarningMessage(`⚠️ ${result.message}`);
        }
    }
}

/**
 * Stop watching for file close events
 */
export function stopWatching(): void {
    if (disposable) {
        disposable.dispose();
        disposable = undefined;
    }
}

/**
 * Manually encrypt the current file
 */
export async function encryptCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
        vscode.window.showWarningMessage('No file is currently open');
        return;
    }

    const document = editor.document;

    if (document.uri.scheme !== 'file') {
        vscode.window.showWarningMessage('Cannot encrypt unsaved files');
        return;
    }

    const filePath = document.uri.fsPath;
    const config = getConfig();

    // Check if file matches pattern
    if (!matchesPatterns(path.basename(filePath), config.patterns)) {
        vscode.window.showWarningMessage('This file does not match .env patterns');
        return;
    }

    // Save the document first
    await document.save();

    // Encrypt
    showStatus('$(sync~spin) Encrypting...', 10000);
    const result = await encryptFile(filePath);

    if (result.success) {
        showStatus('$(check) Encrypted', 3000);
        vscode.window.showInformationMessage(`🔐 ${result.message}`);
    } else {
        showStatus('$(error) Failed', 3000);
        vscode.window.showErrorMessage(`❌ ${result.message}`);
    }
}
