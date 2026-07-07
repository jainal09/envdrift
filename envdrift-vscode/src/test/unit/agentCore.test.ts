import * as assert from 'assert';
import { checkAgentStatus, startAgentCore, stopAgentCore } from '../../agentCore';
import { createShim, writeShimState, Shim } from './shim';

// Regression tests for issue #482, driving the real child_process code paths
// in agentCore.ts against a PATH-shimmed `envdrift-agent` whose behavior is a
// verbatim capture of the real Go binary:
//   - `version` is a subcommand (exit 0); `--version` is an unknown flag (exit 1)
//   - `status` prints `Installed:/Running:/Config:/envdrift:` lines, exit 0
//   - `start` runs the guardian in the FOREGROUND until killed
//   - `install` configures and starts the platform service, then returns
// (tests/test_vscode_cli_contract.py re-validates this contract against the
// real binary so the shim cannot drift.)
const AGENT_SHIM = `
record();
const cmd = args[0];
if (cmd === 'version') {
    process.stdout.write('envdrift-agent 9.9.9-test\\n');
    process.exit(0);
} else if (cmd === '--version') {
    process.stderr.write('Error: unknown flag: --version\\n');
    process.exit(1);
} else if (cmd === 'status') {
    const s = readState();
    process.stdout.write('Installed: true\\n');
    process.stdout.write('Running:   ' + (s.running ? 'true' : 'false') + '\\n');
    process.stdout.write('Config:    /home/user/.envdrift/guardian.toml\\n');
    process.stdout.write('envdrift:  true\\n');
    process.exit(0);
} else if (cmd === 'install') {
    writeState({ running: true });
    process.stdout.write('Agent installed and will start on system boot\\n');
    process.exit(0);
} else if (cmd === 'start') {
    process.stdout.write('Starting envdrift-agent in foreground...\\n');
    // Foreground guardian: stays alive until killed (like the real binary).
    setTimeout(() => process.exit(0), 30000);
} else if (cmd === 'stop') {
    writeState({ running: false });
    process.stdout.write('Agent stopped\\n');
    process.exit(0);
} else {
    process.stderr.write('Error: unknown command "' + cmd + '" for "envdrift-agent"\\n');
    process.exit(1);
}
`;

// Builds an agent shim whose `version`/`status` report a fixed running state,
// but whose action command (`install`/`stop`) exits non-zero — modelling a
// service manager that warns, or a no-op stop on an already-idle unit, while
// still leaving the agent in the target state. Used to prove start/stop trust
// the verified post-action state over the action's exit code (truthful
// reporting, not exit-code guessing).
function flakyActionShim(opts: { running: boolean; failingCmd: 'install' | 'stop' }): Shim {
    const runningLine = opts.running ? 'true' : 'false';
    return createShim({
        'envdrift-agent': `
record();
const cmd = args[0];
if (cmd === 'version') {
    process.stdout.write('envdrift-agent 9.9.9-test\\n');
    process.exit(0);
} else if (cmd === 'status') {
    process.stdout.write('Installed: true\\n');
    process.stdout.write('Running:   ${runningLine}\\n');
    process.stdout.write('Config:    /home/user/.envdrift/guardian.toml\\n');
    process.stdout.write('envdrift:  true\\n');
    process.exit(0);
} else if (cmd === '${opts.failingCmd}') {
    process.stderr.write('${opts.failingCmd}: non-zero exit (service-manager warning / idle no-op)\\n');
    process.exit(1);
} else {
    process.exit(1);
}
`,
    });
}

suite('agentCore against a PATH-shimmed envdrift-agent (#482)', function () {
    this.timeout(30000);

    let shim: Shim;

    setup(() => {
        shim = createShim({ 'envdrift-agent': AGENT_SHIM });
    });

    teardown(() => {
        shim.dispose();
    });

    test('detects an installed-but-stopped agent as stopped, with its version', async () => {
        const status = await checkAgentStatus();
        assert.strictEqual(
            status.status,
            'stopped',
            `expected stopped, got ${status.status} (${status.error ?? 'no error'})`
        );
        assert.strictEqual(status.version, '9.9.9-test');

        // One `version` probe serves both the installed check and the
        // version lookup — a status poll must not spawn the binary twice.
        const spawned = shim.calls().map((argv) => argv[0]);
        assert.deepStrictEqual(
            spawned,
            ['version', 'status'],
            `expected exactly one version probe and one status call, got: ${spawned.join(', ')}`
        );
    });

    test('detects a running agent as running', async () => {
        writeShimState(shim, { running: true });
        const status = await checkAgentStatus();
        assert.strictEqual(status.status, 'running');
        assert.strictEqual(status.version, '9.9.9-test');
    });

    test('start launches the daemonized service, never the foreground debug command', async () => {
        const result = await startAgentCore();
        assert.strictEqual(result.ok, true, `start failed: ${result.error ?? 'unknown'}`);

        const spawned = shim.calls().map((argv) => argv[0]);
        assert.ok(
            spawned.includes('install'),
            `expected the daemonized install path, got: ${spawned.join(', ')}`
        );
        assert.ok(
            !spawned.includes('start'),
            'must not exec the foreground-only `start` command under a timeout'
        );

        // The result carries the verified post-action status so the UI layer
        // can render it without spawning another status check.
        assert.strictEqual(result.status.status, 'running');

        const status = await checkAgentStatus();
        assert.strictEqual(status.status, 'running');
    });

    test('stop stops the agent and reports truthfully', async () => {
        writeShimState(shim, { running: true });
        const result = await stopAgentCore();
        assert.strictEqual(result.ok, true, `stop failed: ${result.error ?? 'unknown'}`);
        assert.strictEqual(result.status.status, 'stopped');

        const status = await checkAgentStatus();
        assert.strictEqual(status.status, 'stopped');
    });

    test('stop reports success when the agent verifies stopped despite a non-zero exit', async () => {
        // Regression: the catch block returned ok:false unconditionally, so an
        // idempotent stop that exits non-zero on an already-idle service was
        // reported as a failure even though the agent is genuinely stopped.
        const flaky = flakyActionShim({ running: false, failingCmd: 'stop' });
        try {
            const result = await stopAgentCore();
            assert.strictEqual(
                result.ok,
                true,
                `stop must report success when verified stopped: ${result.error ?? 'no error'}`
            );
            assert.strictEqual(result.status.status, 'stopped');
        } finally {
            flaky.dispose();
        }
    });

    test('start reports success when the agent verifies running despite a non-zero exit', async () => {
        // Symmetric regression: `install` exiting non-zero after a
        // service-manager warning must not mask a genuinely running agent.
        const flaky = flakyActionShim({ running: true, failingCmd: 'install' });
        try {
            const result = await startAgentCore();
            assert.strictEqual(
                result.ok,
                true,
                `start must report success when verified running: ${result.error ?? 'no error'}`
            );
            assert.strictEqual(result.status.status, 'running');
        } finally {
            flaky.dispose();
        }
    });

    test('reports not_installed when the binary is absent from PATH', async () => {
        // Replace PATH with an empty dir so `envdrift-agent` cannot resolve.
        const emptyShim = createShim({});
        const oldPath = process.env.PATH;
        process.env.PATH = emptyShim.dir;
        try {
            const status = await checkAgentStatus();
            assert.strictEqual(status.status, 'not_installed');
        } finally {
            process.env.PATH = oldPath;
            emptyShim.dispose();
        }
    });
});
