/**
 * Encryption core — locates the envdrift CLI and encrypts files with it.
 * Free of VS Code API imports so it can be unit tested with the real
 * subprocess machinery; the argv it spawns is validated against the real
 * CLI in tests/test_vscode_cli_contract.py.
 */
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { isContentEncrypted } from './utils';

const ENCRYPTION_TIMEOUT_MS = 30000; // 30 second timeout

/**
 * Optional sink for diagnostic messages (wired to the EnvDrift output
 * channel by the extension; no-op in unit tests).
 */
export type LogSink = (message: string) => void;

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
        const content = await fs.promises.readFile(filePath, { encoding: 'utf8' });
        return isContentEncrypted(content);
    } catch {
        return false;
    }
}

/**
 * Encrypt a .env file using the envdrift CLI
 */
export async function encryptFile(
    filePath: string,
    log: LogSink = () => undefined
): Promise<{ success: boolean; message: string }> {
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
            message: process.platform === 'win32'
                ? 'envdrift not found. Install it: irm https://raw.githubusercontent.com/jainal09/envdrift/main/install.ps1 | iex'
                : 'envdrift not found. Install it: curl -sSL https://raw.githubusercontent.com/jainal09/envdrift/main/install.sh | sh',
        };
    }

    const cwd = path.dirname(filePath);
    const fileName = path.basename(filePath);

    try {
        // Use spawn with args array to prevent command injection.
        // Per-file encryption is `envdrift encrypt <file>` — `lock` accepts
        // no positional argument and always exited 2 here (#482).
        const args = [...envdriftInfo.args, 'encrypt', fileName];
        log(`Running: ${envdriftInfo.executable} ${args.join(' ')} (cwd: ${cwd})`);
        await spawnWithTimeout(envdriftInfo.executable, args, cwd, ENCRYPTION_TIMEOUT_MS);

        // Verify the post-condition instead of trusting the exit code: never
        // report success while the file is still plaintext.
        if (!(await isEncrypted(filePath))) {
            const message = `Encryption command succeeded but ${fileName} is still not encrypted`;
            log(message);
            return { success: false, message };
        }

        return {
            success: true,
            message: `Encrypted: ${fileName}`,
        };
    } catch (error) {
        log(`Encryption failed for ${fileName}: ${error}`);
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
