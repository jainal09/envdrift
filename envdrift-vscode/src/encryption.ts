import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

/**
 * Find envdrift CLI
 */
export async function findEnvdrift(): Promise<string | null> {
    const candidates = [
        'envdrift',
        'python -m envdrift',
        'python3 -m envdrift',
    ];

    for (const candidate of candidates) {
        try {
            await execCommand(`${candidate} --version`);
            return candidate;
        } catch {
            // Try next candidate
        }
    }

    return null;
}

/**
 * Check if a file is already encrypted
 */
export async function isEncrypted(filePath: string): Promise<boolean> {
    try {
        const document = await vscode.workspace.openTextDocument(filePath);
        const content = document.getText();

        const lines = content.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('#')) {
                continue;
            }
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
 * Encrypt a .env file using envdrift lock
 */
export async function encryptFile(filePath: string): Promise<{ success: boolean; message: string }> {
    // Check if already encrypted
    if (await isEncrypted(filePath)) {
        return {
            success: true,
            message: 'File is already encrypted',
        };
    }

    const envdrift = await findEnvdrift();
    if (!envdrift) {
        return {
            success: false,
            message: 'envdrift not found. Install it: pip install envdrift',
        };
    }

    const cwd = path.dirname(filePath);
    const fileName = path.basename(filePath);

    try {
        // Use envdrift lock - respects envdrift.toml, vault, ephemeral keys
        await execCommand(`${envdrift} lock "${fileName}"`, cwd);

        return {
            success: true,
            message: `Encrypted: ${fileName}`,
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

