import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import { getConfig } from './config';

/**
 * Find envdrift CLI - falls back to dotenvx if envdrift not available
 */
export async function findEnvdrift(): Promise<{ cmd: string; useEnvdrift: boolean }> {
    // Try envdrift first (respects envdrift.toml, vault, ephemeral keys)
    const envdriftCandidates = [
        'envdrift',
        'python -m envdrift',
        'python3 -m envdrift',
    ];

    for (const candidate of envdriftCandidates) {
        try {
            await execCommand(`${candidate} --version`);
            return { cmd: candidate, useEnvdrift: true };
        } catch {
            // Try next candidate
        }
    }

    // Fallback to dotenvx (direct encryption, no envdrift features)
    const config = getConfig();
    if (config.dotenvxPath) {
        try {
            await execCommand(`"${config.dotenvxPath}" --version`);
            return { cmd: config.dotenvxPath, useEnvdrift: false };
        } catch {
            // Fall through
        }
    }

    const dotenvxCandidates = [
        'dotenvx',
        '/usr/local/bin/dotenvx',
        '/opt/homebrew/bin/dotenvx',
    ];

    for (const candidate of dotenvxCandidates) {
        try {
            await execCommand(`${candidate} --version`);
            return { cmd: candidate, useEnvdrift: false };
        } catch {
            // Try next candidate
        }
    }

    // Ultimate fallback: npx dotenvx
    return { cmd: 'npx -y @dotenvx/dotenvx', useEnvdrift: false };
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
 * Encrypt a .env file using envdrift lock (preferred) or dotenvx
 */
export async function encryptFile(filePath: string): Promise<{ success: boolean; message: string }> {
    // Check if already encrypted
    if (await isEncrypted(filePath)) {
        return {
            success: true,
            message: 'File is already encrypted',
        };
    }

    const { cmd, useEnvdrift } = await findEnvdrift();
    const cwd = path.dirname(filePath);
    const fileName = path.basename(filePath);

    try {
        let command: string;
        if (useEnvdrift) {
            // Use envdrift lock - respects envdrift.toml, vault, ephemeral keys
            command = `${cmd} lock "${fileName}"`;
        } else {
            // Fallback to direct dotenvx - no envdrift features
            command = cmd.startsWith('npx ')
                ? `${cmd} encrypt -f "${filePath}"`
                : `"${cmd}" encrypt -f "${filePath}"`;
        }

        await execCommand(command, cwd);

        const method = useEnvdrift ? 'envdrift' : 'dotenvx';
        return {
            success: true,
            message: `Encrypted: ${fileName} (via ${method})`,
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

