import * as assert from 'assert';
import { isContentEncrypted } from '../../utils';

// Regression tests for issue #482: `isEncrypted()` false-positives on
// plaintext. The predicate must match dotenvx's real format only — an
// `encrypted:` value *prefix* and a real DOTENV_PUBLIC_KEY *assignment* —
// matching the CLI's EncryptionDetector and the Go agent's anchored check.
suite('isContentEncrypted matches the real dotenvx format only (#482)', () => {
    test('plaintext value containing "encrypted:" as a substring is NOT encrypted', () => {
        const content = 'NOTE="backups are encrypted: false"\nDB_PASSWORD=plain_test_value\n';
        assert.strictEqual(isContentEncrypted(content), false);
    });

    test('value with "encrypted:" mid-string is NOT encrypted', () => {
        assert.strictEqual(isContentEncrypted('GREETING=hello encrypted: world\n'), false);
        assert.strictEqual(isContentEncrypted('NOTE=not encrypted: yet\n'), false);
    });

    test('comment mentioning DOTENV_PUBLIC_KEY is NOT evidence of encryption', () => {
        const content = '# Set DOTENV_PUBLIC_KEY before running dotenvx\nAPI_KEY=plain_test_value\n';
        assert.strictEqual(isContentEncrypted(content), false);
    });

    test('a real DOTENV_PUBLIC_KEY assignment IS evidence of encryption', () => {
        assert.strictEqual(isContentEncrypted('DOTENV_PUBLIC_KEY="03abc123"\n'), true);
    });

    test('per-environment DOTENV_PUBLIC_KEY_<ENV> assignment IS evidence of encryption', () => {
        assert.strictEqual(isContentEncrypted('DOTENV_PUBLIC_KEY_PRODUCTION="03abc123"\n'), true);
    });

    test('DOTENV_PUBLIC_KEYSTORE lookalike variable is NOT evidence of encryption', () => {
        assert.strictEqual(isContentEncrypted('DOTENV_PUBLIC_KEYSTORE="something"\n'), false);
    });

    test('an empty DOTENV_PUBLIC_KEY assignment is NOT evidence of encryption', () => {
        assert.strictEqual(isContentEncrypted('DOTENV_PUBLIC_KEY=""\n'), false);
        assert.strictEqual(isContentEncrypted('DOTENV_PUBLIC_KEY=\n'), false);
    });

    test('anchored "encrypted:" value prefix IS encrypted (quoted and unquoted)', () => {
        assert.strictEqual(isContentEncrypted('API_KEY="encrypted:abc123"\n'), true);
        assert.strictEqual(isContentEncrypted("API_KEY='encrypted:abc123'\n"), true);
        assert.strictEqual(isContentEncrypted('API_KEY=encrypted:abc123\n'), true);
    });

    test('value prefix match is case-insensitive (parity with the Go agent)', () => {
        assert.strictEqual(isContentEncrypted('API_KEY="ENCRYPTED:abc123"\n'), true);
    });

    test('a full real dotenvx-encrypted file IS encrypted', () => {
        const content = [
            '#/-------------------[DOTENV_PUBLIC_KEY]--------------------/',
            '#/            public-key encryption for .env files          /',
            '#/----------------------------------------------------------/',
            'DOTENV_PUBLIC_KEY="03f4k3publickey"',
            '',
            '# .env.production',
            'API_KEY="encrypted:f4k3ciphertext"',
            '',
        ].join('\n');
        assert.strictEqual(isContentEncrypted(content), true);
    });

    test('plain env file with secrets is NOT encrypted', () => {
        const content = 'API_KEY=plain_test_value\nDATABASE_URL=postgres://localhost:5432/db\n';
        assert.strictEqual(isContentEncrypted(content), false);
    });

    test('SOPS-encrypted values ARE encrypted (envdrift.toml may use the sops backend)', () => {
        const content = 'API_KEY=ENC[AES256_GCM,data:f4k3,iv:f4k3,tag:f4k3,type:str]\n';
        assert.strictEqual(isContentEncrypted(content), true);
    });

    test('a plaintext value merely mentioning ENC[ mid-string is NOT encrypted', () => {
        assert.strictEqual(
            isContentEncrypted('NOTE="values use ENC[AES256_GCM, envelopes"\n'),
            false
        );
    });
});
