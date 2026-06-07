import * as assert from 'assert';
import { isExcluded } from '../../utils';

suite('isExcluded — glob pattern matching (V4)', () => {
    suite('exact name', () => {
        test('matches exact basename', () => {
            assert.strictEqual(isExcluded('.env.example', ['.env.example']), true);
        });
        test('does not match a different name', () => {
            assert.strictEqual(isExcluded('.env.local', ['.env.example']), false);
        });
        test('matches exact name even when given a full path', () => {
            assert.strictEqual(isExcluded('/path/to/.env.example', ['.env.example']), true);
        });
    });

    suite('suffix glob "*.local"', () => {
        test('matches .env.local', () => {
            assert.strictEqual(isExcluded('.env.local', ['*.local']), true);
        });
        test('matches app.local', () => {
            assert.strictEqual(isExcluded('app.local', ['*.local']), true);
        });
        test('matches via full path (basename .env.local)', () => {
            assert.strictEqual(isExcluded('/a/b/.env.local', ['*.local']), true);
        });
        test('does not match .env.production', () => {
            assert.strictEqual(isExcluded('.env.production', ['*.local']), false);
        });
    });

    suite('prefix glob ".env.*"', () => {
        test('matches .env.production', () => {
            assert.strictEqual(isExcluded('.env.production', ['.env.*']), true);
        });
        test('matches .env.local', () => {
            assert.strictEqual(isExcluded('.env.local', ['.env.*']), true);
        });
        // Guard the regex-escaping edge: the literal "." must NOT act as a wildcard.
        test('does not match "Xenv.local" (dot is literal, not any-char)', () => {
            assert.strictEqual(isExcluded('Xenv.local', ['.env.*']), false);
        });
        test('does not match a bare ".env" (pattern requires a trailing segment)', () => {
            // ".env.*" -> /^\.env\..*$/  : ".env" has no dot after "env"
            assert.strictEqual(isExcluded('.env', ['.env.*']), false);
        });
    });

    suite('mixed exclude lists & negatives', () => {
        const ex = ['.env.example', '.env.sample', '.env.keys', '*.local', '.env.*'];
        test('".env.keys" excluded by literal', () => {
            assert.strictEqual(isExcluded('.env.keys', ex), true);
        });
        test('".env.local" excluded (by *.local and .env.*)', () => {
            assert.strictEqual(isExcluded('.env.local', ex), true);
        });
        test('empty exclude list excludes nothing', () => {
            assert.strictEqual(isExcluded('.env.example', []), false);
        });
    });
});
