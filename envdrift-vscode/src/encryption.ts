import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import { getConfig } from './config';

/**
 * Find dotenvx binary path
 */
export async function findDotenvx(): Promise<string | null> {
    const config = getConfig();

    // Check custom path first
    if (config.dotenvxPath) {
        return config.dotenvxPath;
    }

    // Common locations
    const candidates = [
        'dotenvx',
        '/usr/local/bin/dotenvx',
        '/opt/homebrew/bin/dotenvx',
    ];

    for (const candidate of candidates) {
        try {
            await execCommand(`${candidate} --version`);
            return candidate;
        } catch {
            // Try next candidate
        }
    }

    // Try npx
    try {
        await execCommand('npx dotenvx --version');
        return 'npx dotenvx';
    } catch {
        return null;
    }
}

/**
 * Check if a file is already encrypted
 */
export async function isEncrypted(filePath: string): Promise<boolean> {
    try {
        const document = await vscode.workspace.openTextDocument(filePath);
        const content = document.getText();

        // Check for encrypted marker (dotenvx format)
        const lines = content.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            // Skip comments
            if (trimmed.startsWith('#')) {
                continue;
            }
            // Check for encrypted value
            if (trimmed.toLowerCase().includes('encrypted:')) {
                return true;
            }
        }
        return false;
    } catch {
        return false;
    }
}

/**
 * Encrypt a .env file using dotenvx
 */
export async function encryptFile(filePath: string): Promise<{ success: boolean; message: string }> {
    const dotenvx = await findDotenvx();

    if (!dotenvx) {
        return {
            success: false,
            message: 'dotenvx not found. Please install it: npm install -g @dotenvx/dotenvx',
        };
    }

    // Check if already encrypted
    if (await isEncrypted(filePath)) {
        return {
            success: true,
            message: 'File is already encrypted',
        };
    }

    try {
        const command = dotenvx.startsWith('npx ')
            ? `${dotenvx} encrypt -f "${filePath}"`
            : `"${dotenvx}" encrypt -f "${filePath}"`;

        await execCommand(command, path.dirname(filePath));

        return {
            success: true,
            message: `Encrypted: ${path.basename(filePath)}`,
        };
    } catch (error) {
        return {
            success: false,
            message: `Encryption failed: ${error}`,
        };
    }
}

/**
 * Execute a shell command
 */
function execCommand(command: string, cwd?: string): Promise<string> {
    return new Promise((resolve, reject) => {
        cp.exec(command, { cwd }, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(stderr || error.message));
            } else {
                resolve(stdout);
            }
        });
    });
}
