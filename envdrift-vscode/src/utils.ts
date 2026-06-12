/**
 * Pure utility functions that don't depend on VS Code APIs.
 * These can be unit tested outside of VS Code.
 */

/**
 * Test a single basename against one glob pattern.
 * Supports `*` (matches any run of chars); all other chars are literal.
 * Pure + deterministic — safe to unit test outside VS Code.
 */
function matchesGlob(baseName: string, pattern: string): boolean {
    // Escape regex special chars except *, then convert * to .*
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$');
    return regex.test(baseName);
}

/**
 * Check if a file matches the given patterns
 */
export function matchesPatterns(fileName: string, patterns: string[]): boolean {
    // Handle both forward slashes and backslashes for cross-platform support
    const baseName = fileName.split(/[/\\]/).pop() || fileName;
    return patterns.some(pattern => matchesGlob(baseName, pattern));
}

/**
 * Check if a file should be excluded.
 * Exclude entries are glob patterns (same semantics as `patterns`),
 * so wildcard excludes like `*.keys` or `.env.*.local` work.
 */
export function isExcluded(fileName: string, exclude: string[]): boolean {
    // Handle both forward slashes and backslashes for cross-platform support
    const baseName = fileName.split(/[/\\]/).pop() || fileName;
    return exclude.some(pattern => matchesGlob(baseName, pattern));
}

/**
 * dotenvx's public-key artifact: the exact `DOTENV_PUBLIC_KEY` default or the
 * per-environment `DOTENV_PUBLIC_KEY_<ENV>` form — but not an unrelated
 * variable that merely shares the prefix (e.g. `DOTENV_PUBLIC_KEYSTORE`).
 * Mirrors the CLI's `is_dotenvx_public_key_var` (src/envdrift/core/encryption.py).
 */
const DOTENVX_PUBLIC_KEY_NAME = /^DOTENV_PUBLIC_KEY(_[A-Za-z0-9_]+)?$/;

/**
 * One parsed `NAME=value` line of a .env file.
 */
interface EnvAssignment {
    name: string;
    value: string;
}

/**
 * Parse one .env line into a `NAME=value` assignment. Returns null for
 * blank lines, comments (a comment mentioning DOTENV_PUBLIC_KEY is not
 * evidence of encryption) and non-assignment lines. Strips the surrounding
 * quotes dotenvx writes around values.
 */
function parseEnvAssignment(line: string): EnvAssignment | null {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
        return null;
    }
    const eq = trimmed.indexOf('=');
    if (eq < 0) {
        return null;
    }
    const name = trimmed.slice(0, eq).trim();
    const value = trimmed
        .slice(eq + 1)
        .trim()
        .replace(/^["']/, '')
        .replace(/["']$/, '');
    return { name, value };
}

/**
 * Does one parsed assignment prove the file is encrypted?
 * - a real DOTENV_PUBLIC_KEY assignment (with a value) marks the file;
 * - dotenvx encrypted values start with `encrypted:`;
 * - SOPS encrypted values start with the canonical envelope (parity with
 *   the CLI's SOPS_ENCRYPTED_PATTERN; the [encryption] backend in
 *   envdrift.toml may be sops).
 */
function isEncryptedAssignment(assignment: EnvAssignment): boolean {
    const { name, value } = assignment;
    return (
        (DOTENVX_PUBLIC_KEY_NAME.test(name) && value.length > 0) ||
        value.toLowerCase().startsWith('encrypted:') ||
        value.startsWith('ENC[AES256_GCM,')
    );
}

/**
 * Check if content appears to be encrypted (dotenvx format).
 *
 * Matches dotenvx's real on-disk format only — `encrypted:` anchored as the
 * value *prefix* and a real DOTENV_PUBLIC_KEY *assignment* — in parity with
 * the CLI's EncryptionDetector and the Go agent's `encrypt.IsEncrypted`.
 * Substring heuristics false-positived on plaintext like
 * `NOTE="backups are encrypted: false"` and on comments that merely mention
 * DOTENV_PUBLIC_KEY, silently skipping encryption of real secrets (#482).
 */
export function isContentEncrypted(content: string): boolean {
    return content.split('\n').some((line) => {
        const assignment = parseEnvAssignment(line);
        return assignment !== null && isEncryptedAssignment(assignment);
    });
}

/**
 * Classification of `envdrift-agent status` stdout.
 */
export type ParsedAgentRunState = 'running' | 'stopped' | 'unknown';

/**
 * Classify the stdout of `envdrift-agent status`.
 *
 * The agent prints a `Running:   true|false` line (see envdrift-agent
 * internal/cmd/root.go runStatus); parse that boolean. Substring heuristics
 * misread the literal "Running:" label as the running state, so an
 * installed-but-stopped agent showed green while files stayed plaintext
 * (#482). Unrecognized output is 'unknown' — never assumed running.
 */
export function parseAgentStatusOutput(stdout: string): ParsedAgentRunState {
    const match = /^\s*running:\s*(true|false)\b/im.exec(stdout);
    if (!match) {
        return 'unknown';
    }
    return match[1] === 'true' ? 'running' : 'stopped';
}

/**
 * The subset of `WorkspaceConfiguration.inspect()` results the scope picker
 * needs (kept structural so it is unit-testable outside VS Code).
 */
export interface ConfigScopeValues {
    globalValue?: unknown;
    workspaceValue?: unknown;
    workspaceFolderValue?: unknown;
}

export type ConfigTargetScope = 'global' | 'workspace' | 'workspaceFolder';

/**
 * Pick the configuration scope a toggle should write to: the most specific
 * scope that currently defines the value (mirroring VS Code's own
 * precedence), falling back to global. Always writing Global left a
 * workspace-defined `envdrift.enabled` shadowing the toggle forever while
 * the UI announced a state change that never took effect (#482).
 */
export function pickConfigTargetScope(info: ConfigScopeValues | undefined): ConfigTargetScope {
    if (info?.workspaceFolderValue !== undefined) {
        return 'workspaceFolder';
    }
    if (info?.workspaceValue !== undefined) {
        return 'workspace';
    }
    return 'global';
}
