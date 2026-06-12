/**
 * Cross-platform PATH shim helpers for unit tests (#482).
 *
 * Creates a temp directory containing fake `envdrift-agent` / `envdrift`
 * executables (a POSIX shell wrapper plus a Windows .cmd wrapper, both
 * delegating to a Node script) and prepends it to PATH, so the real
 * child_process code paths in agentCore.ts / encryption.ts run against a
 * deterministic binary. The shim's canned outputs are verbatim captures from
 * the real binaries, and tests/test_vscode_cli_contract.py asserts the real
 * binaries still produce parseable output of the same shape — so the shims
 * cannot silently drift from reality.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface Shim {
    /** Directory that was prepended to PATH. */
    dir: string;
    /** Read the argv of every invocation recorded so far. */
    calls(): string[][];
    /** Remove the shim dir and restore PATH. */
    dispose(): void;
}

/**
 * Write a fake executable named `name` into `dir` that runs `scriptBody`
 * (a Node program source) with the shim dir as cwd.
 */
function writeExecutable(dir: string, name: string, scriptBody: string): void {
    const scriptPath = path.join(dir, `${name}-impl.js`);
    fs.writeFileSync(scriptPath, scriptBody, { encoding: 'utf8' });

    // POSIX wrapper (resolved by /bin/sh from PATH)
    const shPath = path.join(dir, name);
    fs.writeFileSync(
        shPath,
        `#!/bin/sh\nexec "${process.execPath}" "${scriptPath}" "$@"\n`,
        { encoding: 'utf8', mode: 0o755 }
    );

    // Windows wrapper (resolved by cmd.exe from PATH)
    const cmdPath = path.join(dir, `${name}.cmd`);
    fs.writeFileSync(
        cmdPath,
        `@echo off\r\n"${process.execPath}" "${scriptPath}" %*\r\n`,
        { encoding: 'utf8' }
    );
}

/**
 * Create a shim dir exposing the given fake executables and prepend it to
 * PATH. `scripts` maps executable name -> Node program source. Each program
 * can use the injected helpers `record()`, `readState()` and `writeState()`.
 */
export function createShim(scripts: Record<string, string>): Shim {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envdrift-shim-'));
    const callsLog = path.join(dir, 'calls.log');
    const stateFile = path.join(dir, 'state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ running: false }), { encoding: 'utf8' });

    const prelude = `
const fs = require('fs');
const args = process.argv.slice(2);
const CALLS_LOG = ${JSON.stringify(callsLog)};
const STATE_FILE = ${JSON.stringify(stateFile)};
function record() { fs.appendFileSync(CALLS_LOG, JSON.stringify(args) + '\\n', 'utf8'); }
function readState() { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
function writeState(s) { fs.writeFileSync(STATE_FILE, JSON.stringify(s), 'utf8'); }
`;

    for (const [name, body] of Object.entries(scripts)) {
        writeExecutable(dir, name, prelude + body);
    }

    const oldPath = process.env.PATH ?? '';
    process.env.PATH = dir + path.delimiter + oldPath;

    return {
        dir,
        calls(): string[][] {
            if (!fs.existsSync(callsLog)) {
                return [];
            }
            return fs
                .readFileSync(callsLog, { encoding: 'utf8' })
                .split('\n')
                .filter((line) => line.trim().length > 0)
                .map((line) => JSON.parse(line) as string[]);
        },
        dispose(): void {
            process.env.PATH = oldPath;
            fs.rmSync(dir, { recursive: true, force: true });
        },
    };
}

/**
 * Read the shim's mutable state (e.g. whether the fake agent is "running").
 */
export function readShimState(shim: Shim): { running: boolean } {
    return JSON.parse(
        fs.readFileSync(path.join(shim.dir, 'state.json'), { encoding: 'utf8' })
    ) as { running: boolean };
}

/**
 * Mutate the shim's state.
 */
export function writeShimState(shim: Shim, state: { running: boolean }): void {
    fs.writeFileSync(path.join(shim.dir, 'state.json'), JSON.stringify(state), {
        encoding: 'utf8',
    });
}
