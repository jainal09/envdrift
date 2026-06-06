import * as assert from 'assert';
import { matchesPatterns, isExcluded } from '../../utils';

// Mirrors the manual-encrypt gate in fileWatcher.ts (`encryptCurrentFile`):
// a file is encrypted only if it matches a pattern AND is not excluded.
// V3 added the `isExcluded` half to the manual path so it can't lock the
// decryption key (`.env.keys`) or an example file.
const shouldEncrypt = (name: string, patterns: string[], exclude: string[]) =>
    matchesPatterns(name, patterns) && !isExcluded(name, exclude);

suite('manual-encrypt gate honors exclude (V3)', () => {
    const patterns = ['.env*'];
    const exclude = ['.env.example', '*.local', '.env.keys'];

    test('encrypts a matching, non-excluded file', () => {
        assert.strictEqual(shouldEncrypt('.env', patterns, exclude), true);
        assert.strictEqual(shouldEncrypt('.env.production', patterns, exclude), true);
    });
    test('does NOT encrypt an excluded file even on a manual path', () => {
        assert.strictEqual(shouldEncrypt('.env.example', patterns, exclude), false);
        assert.strictEqual(shouldEncrypt('.env.local', patterns, exclude), false); // *.local
        assert.strictEqual(shouldEncrypt('.env.keys', patterns, exclude), false);
    });
    test('does NOT encrypt a non-matching file', () => {
        assert.strictEqual(shouldEncrypt('config.json', patterns, exclude), false);
    });
});
