/**
 * Regression: an `overrides` entry must not break a nested consumer.
 *
 * `overrides` in package.json force a version on EVERY consumer in the tree,
 * bypassing the semver ranges those consumers declare. That is exactly what
 * makes them useful for security floors — and exactly what makes them
 * dangerous.
 *
 * PR #709 added `"brace-expansion": "^5.0.9"` to raise a security floor. It
 * also force-upgraded mocha's nested `minimatch@9.0.9` (which declares
 * `brace-expansion@^2.0.2`) across three majors. brace-expansion 5.x exports a
 * named `expand` with no default, while minimatch 9 compiles to
 * `__importDefault(require("brace-expansion")).default(pattern)` — so any
 * brace pattern threw `TypeError: (0 , brace_expansion_1.default) is not a
 * function` at runtime.
 *
 * `npm audit`, `npm ci`, eslint, tsc and the whole unit suite were all green:
 * plain globs never touch the brace path, so nothing noticed.
 *
 * These tests exercise the real installed module graph. They assert the
 * behaviour (brace expansion works for every minimatch copy in the tree)
 * rather than pinning versions, so they keep protecting us as the tree moves.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';

const EXT_ROOT = path.resolve(__dirname, '..', '..', '..');
const NODE_MODULES = path.join(EXT_ROOT, 'node_modules');

/**
 * Every installed copy of `minimatch`, top-level and nested.
 *
 * Scoped packages install as `@scope/pkg`, so a scope directory is an extra
 * level of nesting with no `node_modules` of its own. Descending into `@*`
 * directories matters: without it, a nested minimatch under
 * `@scope/pkg/node_modules/` would be skipped and this guard would report
 * green while the exact bug it exists to catch was present.
 */
/** Directories to descend into from a package dir: its own tree, or a scope's members. */
function childRoots(dir: string, name: string): string[] {
    // A scope directory (@types, @vscode, …) holds packages, not a node_modules tree.
    if (name.startsWith('@')) {
        return [dir];
    }
    const nested = path.join(dir, 'node_modules');
    return fs.existsSync(nested) ? [nested] : [];
}

/** True when `dir` is a real, requirable minimatch package. */
function isMinimatchPackage(dir: string): boolean {
    // A SCOPED package named minimatch (e.g. @types/minimatch) matches by name
    // but has no runtime entry point, so require() would throw MODULE_NOT_FOUND
    // and fail the suite spuriously. Require a resolvable entry instead of
    // trusting the directory name.
    try {
        require.resolve(dir);
        return true;
    } catch {
        return false;
    }
}

/** Immediate subdirectories of `root`, as [name, fullPath] pairs. */
function subdirectories(root: string): Array<[string, string]> {
    return fs
        .readdirSync(root, { withFileTypes: true })
        .filter((e) => e.isDirectory() || e.isSymbolicLink())
        .map((e) => [e.name, path.join(root, e.name)] as [string, string]);
}

function findMinimatchCopies(root: string, seen = new Set<string>()): string[] {
    if (!fs.existsSync(root)) {
        return [];
    }
    // Cycle-guard by real path rather than a depth cap: npm trees can nest
    // deeper than any fixed limit, and a truncated walk would silently skip a
    // copy — leaving this guard green while the bug it exists to catch was
    // present.
    const key = fs.realpathSync(root);
    if (seen.has(key)) {
        return [];
    }
    seen.add(key);

    return subdirectories(root).flatMap(([name, dir]) =>
        name === 'minimatch' && isMinimatchPackage(dir)
            ? [dir]
            : childRoots(dir, name).flatMap((next) => findMinimatchCopies(next, seen)),
    );
}

suite('package.json overrides stay compatible with nested consumers', () => {
    const copies = findMinimatchCopies(NODE_MODULES);

    test('the module graph is actually installed', () => {
        assert.ok(
            copies.length > 0,
            `no minimatch copies found under ${NODE_MODULES} — run \`npm ci\` first, ` +
                'otherwise every assertion below is vacuous.',
        );
    });

    test('every minimatch copy can expand a brace pattern', () => {
        for (const dir of copies) {
            const version = JSON.parse(
                fs.readFileSync(path.join(dir, 'package.json'), 'utf8'),
            ).version;
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const mod = require(dir);
            const minimatch = mod.minimatch ?? mod;
            const where = `${path.relative(EXT_ROOT, dir)} (v${version})`;

            assert.doesNotThrow(() => {
                minimatch('abc.js', '{abc,def}.js');
            }, `${where}: brace expansion threw — an \`overrides\` entry has forced an incompatible transitive dependency on it.`);

            assert.strictEqual(
                minimatch('abc.js', '{abc,def}.js'),
                true,
                `${where}: brace pattern should match`,
            );
            assert.strictEqual(
                minimatch('zzz.js', '{abc,def}.js'),
                false,
                `${where}: non-matching brace pattern should not match`,
            );
        }
    });

    test('each minimatch copy resolves a brace-expansion satisfying its own range', () => {
        for (const dir of copies) {
            const declared = JSON.parse(
                fs.readFileSync(path.join(dir, 'package.json'), 'utf8'),
            ).dependencies?.['brace-expansion'];
            if (!declared) {
                continue;
            }
            const resolved = path.dirname(
                require.resolve('brace-expansion/package.json', { paths: [dir] }),
            );
            const actual = JSON.parse(
                fs.readFileSync(path.join(resolved, 'package.json'), 'utf8'),
            ).version;

            const declaredMajor = declared.replace(/^[^0-9]*/, '').split('.')[0];
            const actualMajor = actual.split('.')[0];
            assert.strictEqual(
                actualMajor,
                declaredMajor,
                `${path.relative(EXT_ROOT, dir)} declares brace-expansion ${declared} but ` +
                    `resolves ${actual}. A major mismatch here means an \`overrides\` entry ` +
                    'is forcing an API-incompatible version on a nested consumer.',
            );
        }
    });
});
