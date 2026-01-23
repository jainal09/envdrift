/**
 * Pure utility functions that don't depend on VS Code APIs.
 * These can be unit tested outside of VS Code.
 */

/**
 * Check if a file matches the given patterns
 */
export function matchesPatterns(fileName: string, patterns: string[]): boolean {
    const baseName = fileName.split('/').pop() || fileName;
    return patterns.some(pattern => {
        // Escape regex special chars except *, then convert * to .*
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$');
        return regex.test(baseName);
    });
}

/**
 * Check if a file should be excluded
 */
export function isExcluded(fileName: string, exclude: string[]): boolean {
    const baseName = fileName.split('/').pop() || fileName;
    return exclude.includes(baseName);
}

/**
 * Check if content appears to be encrypted (dotenvx format)
 */
export function isContentEncrypted(content: string): boolean {
    const lines = content.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        // Skip empty lines
        if (!trimmed) {
            continue;
        }
        // Check for DOTENV_PUBLIC_KEY header (indicates encrypted file)
        if (trimmed.startsWith('#') && trimmed.includes('DOTENV_PUBLIC_KEY')) {
            return true;
        }
        // Skip other comments
        if (trimmed.startsWith('#')) {
            continue;
        }
        // dotenvx uses "encrypted:" prefix in values
        if (/=.*encrypted:/i.test(trimmed)) {
            return true;
        }
    }
    return false;
}
