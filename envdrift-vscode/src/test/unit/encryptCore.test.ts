import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { encryptFile } from '../../encryption';
import { createShim, Shim } from './shim';

// Regression tests for issue #482, driving the real spawn code path in
// encryption.ts against a PATH-shimmed `envdrift` CLI that mimics the real
// one (per-file encryption is `envdrift encrypt <file>`; `lock` accepts no
// positional argument and exits 2 — both behaviors are re-validated against
// the real CLI in tests/test_vscode_cli_contract.py).
const ENVDRIFT_SHIM = `
record();
const path = require('path');
const cmd = args[0];
const SHIM_DIR = path.dirname(CALLS_LOG);
if (cmd === '--version') {
    process.stdout.write('envdrift 0.0.0-test\\n');
    process.exit(0);
} else if (cmd === 'encrypt') {
    // Mirror Typer: '--' terminates option parsing, so the file is the last
    // positional (the extension spawns \`encrypt -- <file>\`).
    const fileArg = args[args.length - 1];
    if (fs.existsSync(path.join(SHIM_DIR, 'encrypt-noop'))) {
        // Misbehaving-CLI mode: claim success but leave the file plaintext.
        process.stdout.write('Encrypted ' + fileArg + ' using dotenvx\\n');
        process.exit(0);
    }
    const target = path.resolve(process.cwd(), fileArg);
    const encrypted = [
        '#/-------------------[DOTENV_PUBLIC_KEY]--------------------/',
        '#/            public-key encryption for .env files          /',
        '#/----------------------------------------------------------/',
        'DOTENV_PUBLIC_KEY="03f4k3publickey"',
        '',
        'API_KEY="encrypted:f4k3ciphertext"',
        '',
    ].join('\\n');
    fs.writeFileSync(target, encrypted, 'utf8');
    process.stdout.write('Encrypted ' + fileArg + ' using dotenvx\\n');
    process.exit(0);
} else if (cmd === 'lock') {
    if (args.length > 1) {
        process.stderr.write('Got unexpected extra argument(s) (' + args.slice(1).join(' ') + ')\\n');
        process.exit(2);
    }
    process.exit(0);
} else {
    process.stderr.write('No such command: ' + cmd + '\\n');
    process.exit(2);
}
`;

suite('encryptFile against a PATH-shimmed envdrift CLI (#482)', function () {
    this.timeout(30000);

    let shim: Shim;
    let workDir: string;

    setup(() => {
        shim = createShim({ envdrift: ENVDRIFT_SHIM });
        workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'envdrift-encrypt-test-'));
    });

    teardown(() => {
        shim.dispose();
        fs.rmSync(workDir, { recursive: true, force: true });
    });

    function envFile(content: string): string {
        const filePath = path.join(workDir, '.env.production');
        fs.writeFileSync(filePath, content, { encoding: 'utf8' });
        return filePath;
    }

    test('encrypts a plaintext file via `encrypt <file>` and verifies the result', async () => {
        const filePath = envFile('API_KEY=plain_test_value\n');

        const result = await encryptFile(filePath);
        assert.strictEqual(result.success, true, `encryption failed: ${result.message}`);

        const cliCalls = shim.calls().filter((argv) => argv[0] !== '--version');
        assert.deepStrictEqual(
            cliCalls,
            [['encrypt', '--', '.env.production']],
            `expected a single 'encrypt -- <file>' spawn, got: ${JSON.stringify(cliCalls)}`
        );

        const content = fs.readFileSync(filePath, { encoding: 'utf8' });
        assert.ok(content.includes('encrypted:'), 'file must actually be encrypted');
        assert.ok(!content.includes('plain_test_value'), 'plaintext must be gone');
    });

    test('reports failure when the CLI exits 0 but the file is left plaintext', async () => {
        fs.writeFileSync(path.join(shim.dir, 'encrypt-noop'), '', { encoding: 'utf8' });
        const filePath = envFile('API_KEY=plain_test_value\n');

        const result = await encryptFile(filePath);
        assert.strictEqual(
            result.success,
            false,
            'must not report success while the file is still plaintext'
        );
        assert.ok(
            /not encrypted/i.test(result.message),
            `message should say the file is still not encrypted, got: ${result.message}`
        );
    });

    test('skips an already-encrypted file without spawning the CLI', async () => {
        const filePath = envFile(
            'DOTENV_PUBLIC_KEY="03f4k3publickey"\nAPI_KEY="encrypted:f4k3ciphertext"\n'
        );

        const result = await encryptFile(filePath);
        assert.strictEqual(result.success, true);
        assert.strictEqual(result.message, 'File is already encrypted');
        assert.deepStrictEqual(shim.calls(), [], 'no CLI process should be spawned');
    });

    test('does NOT treat plaintext containing "encrypted:" substrings as already encrypted', async () => {
        const filePath = envFile(
            'NOTE="backups are encrypted: false"\nDB_PASSWORD=plain_test_value\n'
        );

        const result = await encryptFile(filePath);
        assert.strictEqual(result.success, true, `encryption failed: ${result.message}`);
        assert.notStrictEqual(
            result.message,
            'File is already encrypted',
            'plaintext with an "encrypted:" substring must not be skipped'
        );

        const spawned = shim.calls().map((argv) => argv[0]);
        assert.ok(spawned.includes('encrypt'), 'the CLI must be invoked for this plaintext file');

        const content = fs.readFileSync(filePath, { encoding: 'utf8' });
        assert.ok(content.includes('DOTENV_PUBLIC_KEY="03'), 'file must end up really encrypted');
    });
});
