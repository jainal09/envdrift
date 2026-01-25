import * as assert from 'assert';
import { matchesPatterns, isExcluded, isContentEncrypted } from '../../utils';

suite('Config Unit Tests', () => {
    suite('matchesPatterns', () => {
        test('should match .env file with .env* pattern', () => {
            assert.strictEqual(matchesPatterns('.env', ['.env*']), true);
        });

        test('should match .env.local with .env* pattern', () => {
            assert.strictEqual(matchesPatterns('.env.local', ['.env*']), true);
        });

        test('should match .env.production with .env* pattern', () => {
            assert.strictEqual(matchesPatterns('.env.production', ['.env*']), true);
        });

        test('should not match config.json with .env* pattern', () => {
            assert.strictEqual(matchesPatterns('config.json', ['.env*']), false);
        });

        test('should match exact filename pattern', () => {
            assert.strictEqual(matchesPatterns('.env', ['.env']), true);
        });

        test('should not match partial filename with exact pattern', () => {
            assert.strictEqual(matchesPatterns('.env.local', ['.env']), false);
        });

        test('should handle multiple patterns', () => {
            assert.strictEqual(matchesPatterns('.env', ['.env*', 'secrets*']), true);
            assert.strictEqual(matchesPatterns('secrets.json', ['.env*', 'secrets*']), true);
            assert.strictEqual(matchesPatterns('config.json', ['.env*', 'secrets*']), false);
        });

        test('should handle full path and extract basename', () => {
            assert.strictEqual(matchesPatterns('/path/to/.env', ['.env*']), true);
            assert.strictEqual(matchesPatterns('/path/to/.env.local', ['.env*']), true);
        });

        test('should handle empty patterns array', () => {
            assert.strictEqual(matchesPatterns('.env', []), false);
        });
    });

    suite('isExcluded', () => {
        test('should exclude .env.example', () => {
            const excludes = ['.env.example', '.env.sample', '.env.keys'];
            assert.strictEqual(isExcluded('.env.example', excludes), true);
        });

        test('should exclude .env.sample', () => {
            const excludes = ['.env.example', '.env.sample', '.env.keys'];
            assert.strictEqual(isExcluded('.env.sample', excludes), true);
        });

        test('should exclude .env.keys', () => {
            const excludes = ['.env.example', '.env.sample', '.env.keys'];
            assert.strictEqual(isExcluded('.env.keys', excludes), true);
        });

        test('should not exclude .env', () => {
            const excludes = ['.env.example', '.env.sample', '.env.keys'];
            assert.strictEqual(isExcluded('.env', excludes), false);
        });

        test('should not exclude .env.local', () => {
            const excludes = ['.env.example', '.env.sample', '.env.keys'];
            assert.strictEqual(isExcluded('.env.local', excludes), false);
        });

        test('should handle full path and extract basename', () => {
            const excludes = ['.env.example'];
            assert.strictEqual(isExcluded('/path/to/.env.example', excludes), true);
            assert.strictEqual(isExcluded('/path/to/.env', excludes), false);
        });

        test('should handle empty excludes array', () => {
            assert.strictEqual(isExcluded('.env.example', []), false);
        });
    });

    suite('isContentEncrypted', () => {
        test('should detect DOTENV_PUBLIC_KEY header', () => {
            const content = `#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/----------------------------------------------------------/
DOTENV_PUBLIC_KEY="abc123"
SECRET="encrypted:xyz"`;
            assert.strictEqual(isContentEncrypted(content), true);
        });

        test('should detect encrypted: prefix in values', () => {
            const content = `API_KEY="encrypted:abc123"
DATABASE_URL="encrypted:xyz789"`;
            assert.strictEqual(isContentEncrypted(content), true);
        });

        test('should return false for plain env file', () => {
            const content = `API_KEY="myapikey"
DATABASE_URL="postgres://localhost:5432/db"
DEBUG=true`;
            assert.strictEqual(isContentEncrypted(content), false);
        });

        test('should handle empty content', () => {
            assert.strictEqual(isContentEncrypted(''), false);
        });

        test('should handle comments without encryption markers', () => {
            const content = `# This is a comment
# Another comment
API_KEY="mykey"`;
            assert.strictEqual(isContentEncrypted(content), false);
        });

        test('should handle mixed content with empty lines', () => {
            const content = `
# Comment

API_KEY="encrypted:secret"

DEBUG=true
`;
            assert.strictEqual(isContentEncrypted(content), true);
        });
    });
});
