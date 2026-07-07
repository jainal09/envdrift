import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { parseAgentStatusOutput } from '../../utils';

// Regression tests for issue #482: the status parser mapped
// installed-but-STOPPED to "running" because /\brunning\b/ matches the
// literal "Running:" label, and the "stopped"/"not running" strings it
// looked for never occur in the agent's real output. The fixtures are
// verbatim captures of `envdrift-agent status`, shared with
// tests/test_vscode_cli_contract.py, which asserts their line shape still
// matches the real binary's output — so the parser inputs cannot drift.
const FIXTURES_DIR = path.resolve(__dirname, '../../../src/test/unit/fixtures');

function fixture(name: string): string {
    return fs.readFileSync(path.join(FIXTURES_DIR, name), { encoding: 'utf8' });
}

const STOPPED_OUTPUT = fixture('agent-status-stopped.txt');
const RUNNING_OUTPUT = fixture('agent-status-running.txt');

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
