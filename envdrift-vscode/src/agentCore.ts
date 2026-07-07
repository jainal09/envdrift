/**
 * Agent CLI integration core — everything that talks to the `envdrift-agent`
 * binary, kept free of VS Code API imports so it can be unit tested with the
 * real subprocess machinery (mocha drives it against a PATH shim, and
 * tests/test_vscode_cli_contract.py validates the argv against the real
 * Go binary).
 */
import { exec } from 'child_process';
import { promisify } from 'util';
import { parseAgentStatusOutput } from './utils';

const execAsync = promisify(exec);

/**
 * Agent status types
 */
export type AgentStatus = 'running' | 'stopped' | 'not_installed' | 'error';

/**
 * Agent status info
 */
export interface AgentStatusInfo {
    status: AgentStatus;
    version?: string;
    error?: string;
}

/**
 * Result of a start/stop action, including the verified post-action status
 * (so callers can render it without spawning another status check).
 */
export interface AgentActionResult {
    ok: boolean;
    error?: string;
    status: AgentStatusInfo;
}

// Timeout for agent subprocess calls (prevents polling hangs on a stuck binary)
export const AGENT_EXEC_TIMEOUT_MS = 10000;

// `install` (re)writes the service unit and starts the platform service
// (launchctl / systemctl --user / schtasks); allow it a little longer.
export const AGENT_INSTALL_TIMEOUT_MS = 30000;

/**
 * Get the agent version (e.g. "1.2.3" from "envdrift-agent 1.2.3"), or
 * undefined when the binary is absent.
 *
 * The agent is a cobra CLI with a `version` subcommand and no `--version`
 * flag — probing the flag made every check return "not_installed" (#482).
 */
async function getAgentVersion(): Promise<string | undefined> {
    try {
        const { stdout } = await execAsync('envdrift-agent version', { timeout: AGENT_EXEC_TIMEOUT_MS });
        return stdout.trim().replace(/^envdrift-agent\s+/, '');
    } catch {
        return undefined;
    }
}

/**
 * Check the current agent status
 */
export async function checkAgentStatus(): Promise<AgentStatusInfo> {
    try {
        // One probe does double duty: `version` failing means the binary is
        // not installed; succeeding yields the version for the status info.
        const version = await getAgentVersion();
        if (version === undefined) {
            return { status: 'not_installed' };
        }

        // Check agent status
        const { stdout } = await execAsync('envdrift-agent status', { timeout: AGENT_EXEC_TIMEOUT_MS });
        const parsed = parseAgentStatusOutput(stdout);

        if (parsed === 'unknown') {
            // Fail loudly instead of guessing a state we cannot verify.
            return {
                status: 'error',
                error: `unrecognized agent status output: ${stdout.trim()}`,
            };
        }

        return { status: parsed, version };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Check if it's a "not found" error
        if (errorMessage.includes('not found') || errorMessage.includes('ENOENT')) {
            return { status: 'not_installed' };
        }

        return { status: 'error', error: errorMessage };
    }
}

/**
 * Start the agent and report whether it is actually running afterwards.
 *
 * `envdrift-agent start` runs the guardian in the FOREGROUND (a debugging
 * command), so exec-ing it under a timeout ran the agent for 10s, killed it,
 * and reported failure (#482). The daemonized path is `envdrift-agent
 * install`: it idempotently (re)writes the platform service unit and starts
 * it (launchctl load / systemctl --user start / schtasks), which is also the
 * supported way to start again after `envdrift-agent stop`.
 */
export async function startAgentCore(): Promise<AgentActionResult> {
    try {
        await execAsync('envdrift-agent install', { timeout: AGENT_INSTALL_TIMEOUT_MS });
        const status = await checkAgentStatus();
        if (status.status === 'running') {
            return { ok: true, status };
        }
        return { ok: false, error: `agent is ${status.status} after start`, status };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        // A non-zero exit does not mean the agent failed to start: `install`
        // can exit non-zero after a service-manager warning while the unit
        // still ends up active. Trust the verified state over the exit code —
        // report success only if the agent actually reached 'running'.
        const status = await checkAgentStatus();
        if (status.status === 'running') {
            return { ok: true, status };
        }
        return { ok: false, error: errorMessage, status };
    }
}

/**
 * Stop the agent and report whether it is actually stopped afterwards.
 */
export async function stopAgentCore(): Promise<AgentActionResult> {
    try {
        // Add timeout to prevent hanging if agent doesn't respond
        await execAsync('envdrift-agent stop', { timeout: AGENT_EXEC_TIMEOUT_MS });
        const status = await checkAgentStatus();
        if (status.status === 'stopped') {
            return { ok: true, status };
        }
        return { ok: false, error: `agent is ${status.status} after stop`, status };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        // A non-zero exit does not mean the stop failed: stopping an already
        // idle service is a no-op that exits non-zero (e.g. `systemctl stop`
        // on an inactive unit). Trust the verified state over the exit code —
        // report success only if the agent actually reached 'stopped'.
        const status = await checkAgentStatus();
        if (status.status === 'stopped') {
            return { ok: true, status };
        }
        return { ok: false, error: errorMessage, status };
    }
}
