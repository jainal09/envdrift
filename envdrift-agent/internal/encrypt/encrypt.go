// Package encrypt handles encryption via the envdrift CLI.
// Requires envdrift CLI to be installed (pip install envdrift).
package encrypt

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrEnvdriftNotFound is returned when envdrift CLI is not installed.
var ErrEnvdriftNotFound = errors.New("envdrift not found. Install it: pip install envdrift")

// dotenvxPublicKeyPrefix marks dotenvx's public-key line (DOTENV_PUBLIC_KEY /
// DOTENV_PUBLIC_KEY_<ENV>). The public key is stored plaintext by design and is
// not a secret, so it must never count as an unencrypted value (mirrors the
// CLI's rules in src/envdrift/core/partial_encryption.py).
const dotenvxPublicKeyPrefix = "DOTENV_PUBLIC_KEY"

// Ciphertext markers of an assigned dotenv VALUE: dotenvx writes
// `KEY="encrypted:..."`, SOPS writes `KEY=ENC[<algo>,...]`. Match the SOPS tag
// on the generic `ENC[` opener rather than a single cipher suite: SOPS emits
// AES256_GCM by default but also supports AES256_SIV / AES256_CTR (and may add
// more), all of which start `ENC[`. Pinning to `ENC[AES256_GCM,` mislabeled
// those as plaintext, so the guardian re-ran `envdrift encrypt` on an
// already-encrypted file every cycle.
const (
	dotenvxCiphertextPrefix = "encrypted:"
	sopsCiphertextPrefix    = "ENC["
)

// sopsMetadataScalarKeys is the fixed set of flat SOPS bookkeeping keys that a
// SOPS-encrypted dotenv file carries in plaintext. They are metadata, not
// secrets, so they must not flag a fully SOPS-encrypted file as mixed-state.
// Mirrors _SOPS_METADATA_SCALAR_KEYS in src/envdrift/core/partial_encryption.py.
var sopsMetadataScalarKeys = map[string]struct{}{
	"sops_version":                   {},
	"sops_mac":                       {},
	"sops_lastmodified":              {},
	"sops_unencrypted_suffix":        {},
	"sops_encrypted_suffix":          {},
	"sops_unencrypted_regex":         {},
	"sops_encrypted_regex":           {},
	"sops_unencrypted_comment_regex": {},
	"sops_encrypted_comment_regex":   {},
	"sops_mac_only_encrypted":        {},
	"sops_shamir_threshold":          {},
}

// sopsMetadataGroupKey matches SOPS's nested key-group provider entries
// (sops_age*/sops_pgp*/...), anchored on the provider token so a real user
// variable like `sops_token` is still treated as a secret. Mirrors
// _SOPS_METADATA_GROUP_KEY in src/envdrift/core/partial_encryption.py.
var sopsMetadataGroupKey = regexp.MustCompile(`^sops_(?:age|pgp|kms|gcp_kms|azure_kv|hc_vault)(?:_|__|$)`)

// IsEncrypted reports whether a .env file is FULLY encrypted: at least one
// assigned value is ciphertext and no plaintext secret value remains.
//
// The pre-#481 predicate returned true as soon as ANY value was encrypted, so a
// mixed-state file — encrypted values plus a freshly added plaintext secret —
// looked "already encrypted" and the guardian dropped it from tracking without
// ever re-encrypting the new secret. Requiring every value line to be
// encrypted (mirroring the CLI's partial-encryption awareness) hands mixed
// files back to the encrypt step, which is idempotent: dotenvx re-encrypts
// only the plaintext values.
func IsEncrypted(path string) (encrypted bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	sawCiphertext := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Anchor to the value of an assignment so a plaintext substring like
		// `NOTE=not encrypted: yet` is not a false positive (#348 G6).
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		// dotenvx's public key and SOPS's metadata trailer are plaintext by
		// design; neither is a secret value.
		if strings.HasPrefix(key, dotenvxPublicKeyPrefix) || isSOPSMetadataKey(key) {
			continue
		}
		value := unquoteValue(line[eq+1:])
		if value == "" {
			// Empty assignment (KEY=, KEY="", KEY='') carries no secret.
			continue
		}
		if isCiphertextValue(value) {
			sawCiphertext = true
			continue
		}
		// A plaintext secret value: the file is not fully encrypted.
		return false, nil
	}
	if serr := scanner.Err(); serr != nil {
		return false, serr
	}

	return sawCiphertext, nil
}

// isCiphertextValue reports whether an unquoted assigned value is genuine
// ciphertext (dotenvx or SOPS format).
func isCiphertextValue(value string) bool {
	// dotenvx prefix match stays case-insensitive (pre-existing behavior).
	return strings.HasPrefix(strings.ToLower(value), dotenvxCiphertextPrefix) ||
		strings.HasPrefix(value, sopsCiphertextPrefix)
}

// isSOPSMetadataKey reports whether key belongs to the exact SOPS metadata
// family (scalar bookkeeping keys or nested provider key-groups) — not a bare
// `sops_` prefix, so a user variable such as `sops_token` is still a secret.
func isSOPSMetadataKey(key string) bool {
	if _, ok := sopsMetadataScalarKeys[key]; ok {
		return true
	}
	return sopsMetadataGroupKey.MatchString(key)
}

// unquoteValue strips surrounding whitespace, an inline `# comment` trailing a
// quoted token, and a single layer of matching quotes, the two styles
// dotenv/SOPS emit (`"..."` and `'...'`).
func unquoteValue(value string) string {
	v := stripCommentAfterQuotedValue(strings.TrimSpace(value))
	if isWrappedInMatchingQuotes(v) {
		v = strings.TrimSpace(v[1 : len(v)-1])
	}
	return v
}

// stripCommentAfterQuotedValue drops an inline `# comment` that follows a
// closed quoted token: dotenv allows `KEY="value" # note`, and the trailing
// comment defeated the matching-quotes check, so quoted ciphertext with an
// inline comment was misclassified as plaintext and the guardian re-ran
// encrypt on the already-encrypted file every idle cycle. Only a comment (or
// nothing) may follow the closing quote — any other trailing token leaves the
// value untouched, so a malformed line still counts as plaintext (the safe
// direction: the worst case is a redundant, idempotent re-encrypt).
func stripCommentAfterQuotedValue(v string) string {
	if len(v) < 2 || (v[0] != '"' && v[0] != '\'') {
		return v
	}
	end := strings.IndexByte(v[1:], v[0])
	if end < 0 {
		return v
	}
	closing := 1 + end
	rest := strings.TrimSpace(v[closing+1:])
	if rest == "" || strings.HasPrefix(rest, "#") {
		return v[:closing+1]
	}
	return v
}

// isWrappedInMatchingQuotes reports whether v opens and closes with the same
// single- or double-quote character (a complete quoted token of length >= 2).
func isWrappedInMatchingQuotes(v string) bool {
	if len(v) < 2 {
		return false
	}
	q := v[0]
	return (q == '"' || q == '\'') && v[len(v)-1] == q
}

// Encrypt encrypts a .env file using the envdrift CLI.
func Encrypt(path string) error {
	cmd, err := buildEncryptCommand(path)
	if err != nil {
		return err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// EncryptSilent encrypts silently without stdout/stderr.
func EncryptSilent(path string) error {
	cmd, err := buildEncryptCommand(path)
	if err != nil {
		return err
	}
	return cmd.Run()
}

// IsEnvdriftAvailable checks if envdrift CLI is available.
func IsEnvdriftAvailable() bool {
	_, _, err := findEnvdrift()
	return err == nil
}

// buildEncryptCommand builds the `envdrift encrypt <file>` command.
//
// `encrypt` is the CLI's per-file encryption path: it takes a positional
// ENV_FILE argument. The pre-#481 code invoked `envdrift lock <file>`, but
// `lock` takes no positional argument — every invocation exited 2 with
// "Got unexpected extra argument(s)" and no file was ever encrypted.
func buildEncryptCommand(path string) (*exec.Cmd, error) {
	dir := filepath.Dir(path)
	fileName := filepath.Base(path)

	envdrift, isPython, err := findEnvdrift()
	if err != nil {
		return nil, ErrEnvdriftNotFound
	}

	var cmd *exec.Cmd
	if isPython {
		// A Python interpreter must be invoked as `python -m envdrift ...`
		// rather than directly (#348 G1).
		cmd = exec.Command(envdrift, "-m", "envdrift", "encrypt", fileName)
	} else {
		cmd = exec.Command(envdrift, "encrypt", fileName)
	}
	cmd.Dir = dir
	return cmd, nil
}

// findEnvdrift locates the envdrift executable. isPython is true when the
// resolved binary is a Python interpreter that must be invoked as
// `python -m envdrift ...` rather than directly.
func findEnvdrift() (path string, isPython bool, err error) {
	// Check if envdrift is in PATH
	if p, lookErr := exec.LookPath("envdrift"); lookErr == nil {
		return p, false, nil
	}

	// Try python3 -m envdrift
	if python, lookErr := exec.LookPath("python3"); lookErr == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return python, true, nil
		}
	}

	// Try python -m envdrift
	if python, lookErr := exec.LookPath("python"); lookErr == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return python, true, nil
		}
	}

	return "", false, exec.ErrNotFound
}
