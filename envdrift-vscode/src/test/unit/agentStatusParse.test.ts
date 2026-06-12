import * as assert from 'assert';
import { parseAgentStatusOutput } from '../../utils';

// Regression tests for issue #482: the status parser mapped
// installed-but-STOPPED to "running" because /\brunning\b/ matches the
// literal "Running:" label, and the "stopped"/"not running" strings it
// looked for never occur in the agent's real output. These fixtures are
// verbatim captures of `envdrift-agent status` (the shape is re-verified
// against the real binary in tests/test_vscode_cli_contract.py).
const STOPPED_OUTPUT = [
    'Installed: true',
    'Running:   false',
    'Config:    /home/user/.envdrift/guardian.toml',
    'envdrift:  true',
    '',
].join('\n');

const RUNNING_OUTPUT = [
    'Installed: true',
    'Running:   true',
    'Config:    /home/user/.envdrift/guardian.toml',
    'envdrift:  true',
    '',
].join('\n');

suite('parseAgentStatusOutput reads the Running: boolean (#482)', () => {
    test('verbatim installed-but-stopped output parses as stopped', () => {
        assert.strictEqual(parseAgentStatusOutput(STOPPED_OUTPUT), 'stopped');
    });

    test('verbatim running output parses as running', () => {
        assert.strictEqual(parseAgentStatusOutput(RUNNING_OUTPUT), 'running');
    });

    test('not-installed-yet output (Installed: false, Running: false) parses as stopped', () => {
        const output = [
            'Installed: false',
            'Running:   false',
            'Config:    /home/user/.envdrift/guardian.toml',
            'envdrift:  true',
            '',
        ].join('\n');
        assert.strictEqual(parseAgentStatusOutput(output), 'stopped');
    });

    test('CRLF output parses (Windows)', () => {
        assert.strictEqual(
            parseAgentStatusOutput(STOPPED_OUTPUT.replace(/\n/g, '\r\n')),
            'stopped'
        );
        assert.strictEqual(
            parseAgentStatusOutput(RUNNING_OUTPUT.replace(/\n/g, '\r\n')),
            'running'
        );
    });

    test('output without a Running: line is unknown, never running', () => {
        assert.strictEqual(parseAgentStatusOutput('something unexpected'), 'unknown');
        assert.strictEqual(parseAgentStatusOutput(''), 'unknown');
    });
});
