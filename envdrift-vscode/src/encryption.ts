import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';

const ENCRYPTION_TIMEOUT_MS = 30000; // 30 second timeout

/**
 * Find envdrift CLI and return executable info
 */
export async function findEnvdrift(): Promise<{ executable: string; args: string[] } | null> {
    // Try envdrift directly
    if (await commandExists('envdrift')) {
        return { executable: 'envdrift', args: [] };
    }

    // Try python3 -m envdrift
    if (await commandExists('python3')) {
        if (await testPythonModule('python3', 'envdrift')) {
            return { executable: 'python3', args: ['-m', 'envdrift'] };
        }
    }

    // Try python -m envdrift
    if (await commandExists('python')) {
        if (await testPythonModule('python', 'envdrift')) {
            return { executable: 'python', args: ['-m', 'envdrift'] };
        }
    }

    return null;
}

/**
 * Check if a command exists (with 5 second timeout)
 */
async function commandExists(cmd: string): Promise<boolean> {
    return new Promise((resolve) => {
        const proc = cp.spawn(cmd, ['--version'], { stdio: 'ignore' });
        const timeout = setTimeout(() => {
            proc.kill('SIGTERM');
            resolve(false);
        }, 5000);
        proc.on('error', () => {
            clearTimeout(timeout);
            resolve(false);
        });
        proc.on('close', (code) => {
            clearTimeout(timeout);
            resolve(code === 0);
        });
    });
}

/**
 * Test if a Python module can be run (with 5 second timeout)
 */
async function testPythonModule(python: string, module: string): Promise<boolean> {
    return new Promise((resolve) => {
        const proc = cp.spawn(python, ['-m', module, '--version'], { stdio: 'ignore' });
        const timeout = setTimeout(() => {
            proc.kill('SIGTERM');
            resolve(false);
        }, 5000);
        proc.on('error', () => {
            clearTimeout(timeout);
            resolve(false);
        });
        proc.on('close', (code) => {
            clearTimeout(timeout);
            resolve(code === 0);
        });
    });
}

/**
 * Check if a file is already encrypted (dotenvx format)
 */
export async function isEncrypted(filePath: string): Promise<boolean> {
    try {
        const document = await vscode.workspace.openTextDocument(filePath);
        const content = document.getText();

        // Check for dotenvx encryption markers
        const lines = content.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            // Skip empty lines
            if (!trimmed) {
                continue;
            }
            // Check for DOTENV_PUBLIC_KEY header (indicates encrypted file)
            if (trimmed.startsWith('#') && trimmed.includes('DOTENV_PUBLIC_KEY')) {
                return true;
            }
            // Skip other comments
            if (trimmed.startsWith('#')) {
                continue;
            }
            // dotenvx uses "encrypted:" prefix in values
            if (/=.*encrypted:/i.test(trimmed)) {
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

    const envdriftInfo = await findEnvdrift();
    if (!envdriftInfo) {
        return {
            success: false,
            message: 'envdrift not found. Install it: pip install envdrift',
        };
    }

    const cwd = path.dirname(filePath);
    const fileName = path.basename(filePath);

    try {
        // Use spawn with args array to prevent command injection
        const args = [...envdriftInfo.args, 'lock', fileName];
        await spawnWithTimeout(envdriftInfo.executable, args, cwd, ENCRYPTION_TIMEOUT_MS);

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
 * Execute a command with timeout using spawn (no shell = no injection)
 */
function spawnWithTimeout(
    command: string,
    args: string[],
    cwd: string,
    timeoutMs: number
): Promise<string> {
    return new Promise((resolve, reject) => {
        const proc = cp.spawn(command, args, { cwd, stdio: 'pipe' });
        let stdout = '';
        let stderr = '';

        const timeout = setTimeout(() => {
            proc.kill('SIGTERM');
            reject(new Error(`Command timed out after ${timeoutMs / 1000}s`));
        }, timeoutMs);

        proc.stdout?.on('data', (data) => { stdout += data.toString(); });
        proc.stderr?.on('data', (data) => { stderr += data.toString(); });

        proc.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
        });

        proc.on('close', (code) => {
            clearTimeout(timeout);
            if (code === 0) {
                resolve(stdout);
            } else {
                reject(new Error(stderr || `Process exited with code ${code}`));
            }
        });
    });
}
