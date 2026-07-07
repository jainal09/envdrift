// Package encrypt tests
package encrypt

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// isEncryptedCase is one table row for the IsEncrypted tests.
type isEncryptedCase struct {
	name     string
	content  string
	expected bool
}

// runIsEncryptedCases writes each case to a temp .env file and asserts the
// IsEncrypted verdict, so the dotenvx and SOPS tables share one harness.
func runIsEncryptedCases(t *testing.T, tests []isEncryptedCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			filePath := filepath.Join(tempDir, ".env.test")
			if err := os.WriteFile(filePath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result, err := IsEncrypted(filePath)
			if err != nil {
				t.Fatalf("IsEncrypted returned error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("IsEncrypted(%q) = %v, expected %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestIsEncrypted(t *testing.T) {
	runIsEncryptedCases(t, []isEncryptedCase{
		{
			name:     "encrypted file",
			content:  "DATABASE_URL=\"encrypted:abc123\"\nAPI_KEY=\"encrypted:xyz789\"",
			expected: true,
		},
		{
			name:     "plaintext file",
			content:  "DATABASE_URL=\"postgres://localhost:5432/db\"\nAPI_KEY=\"sk-secret-key\"",
			expected: false,
		},
		{
			name:     "mixed case encrypted marker",
			content:  "SECRET=\"ENCRYPTED:abc123\"",
			expected: true,
		},
		{
			name:     "empty file",
			content:  "",
			expected: false,
		},
		{
			name:     "comments only",
			content:  "# This is a comment\n# Another comment",
			expected: false,
		},
		{
			name:     "encrypted in comment",
			content:  "# encrypted: values below\nKEY=value",
			expected: false, // Comments should be ignored
		},
		{
			name:     "value with encrypted marker, no quotes",
			content:  "API_KEY=encrypted:abc",
			expected: true,
		},
		{
			// Regression for #348 G6: a plaintext value that merely contains
			// the substring "encrypted:" must not be reported as encrypted.
			name:     "plaintext value containing encrypted substring",
			content:  "NOTE=not encrypted: yet",
			expected: false,
		},
		{
			// The anchor is the value side: "encrypted:" appearing only in the
			// key/free-text without an = value must not match.
			name:     "plaintext mention without assignment",
			content:  "this line says encrypted: nope",
			expected: false,
		},
		{
			// #481 regression: one encrypted value must NOT mark a mixed-state
			// file as fully encrypted — a plaintext secret added to an
			// already-encrypted file would be dropped from tracking and never
			// re-encrypted.
			name: "mixed state: encrypted values plus fresh plaintext secret",
			content: "DOTENV_PUBLIC_KEY=\"03a5b1c2\"\n" +
				"DATABASE_URL=\"encrypted:abc123\"\n" +
				"NEW_SECRET=super-plaintext\n",
			expected: false,
		},
		{
			// The dotenvx public key (and its env-suffixed variants) is stored
			// plaintext by design; it must not flag a fully encrypted file as
			// mixed-state.
			name: "fully encrypted dotenvx file with public-key header",
			content: "#/---- DOTENV_PUBLIC_KEY ----/\n" +
				"DOTENV_PUBLIC_KEY=\"03a5b1c2\"\n" +
				"DOTENV_PUBLIC_KEY_PRODUCTION=\"03d4e5f6\"\n" +
				"DATABASE_URL=\"encrypted:abc123\"\n" +
				"API_KEY=\"encrypted:xyz789\"\n",
			expected: true,
		},
		{
			// Empty assignments carry no secret and must not count as plaintext.
			name: "encrypted file with empty assignments",
			content: "EMPTY=\nQUOTED_EMPTY=\"\"\n" +
				"SECRET=\"encrypted:abc123\"\n",
			expected: true,
		},
		{
			// A public-key line alone is not ciphertext: a decrypted dotenvx
			// file keeps DOTENV_PUBLIC_KEY while its values revert to plaintext.
			name: "decrypted dotenvx file (public key plus plaintext values)",
			content: "DOTENV_PUBLIC_KEY=\"03a5b1c2\"\n" +
				"DATABASE_URL=\"postgres://localhost:5432/db\"\n",
			expected: false,
		},
	})
}

// TestIsEncryptedInlineComments is the #504 cubic review regression: an inline
// `# comment` after the closing quote defeated the matching-quotes check, so a
// quoted ciphertext value was misclassified as plaintext and the guardian
// re-encrypted the already-encrypted file every idle cycle.
func TestIsEncryptedInlineComments(t *testing.T) {
	runIsEncryptedCases(t, []isEncryptedCase{
		{
			name:     "quoted ciphertext with inline comment",
			content:  "SECRET=\"encrypted:abc123\" # rotated 2026-06\n",
			expected: true,
		},
		{
			// The SOPS flavor: an inline comment after the quoted ENC[...]
			// token must not flip it to plaintext either.
			name:     "quoted SOPS ciphertext with inline comment",
			content:  "API_KEY=\"ENC[AES256_GCM,data:xyz,type:str]\" # managed by sops\n",
			expected: true,
		},
		{
			// The comment strip must not turn plaintext into ciphertext: a
			// quoted plaintext value with an inline comment stays plaintext.
			name:     "quoted plaintext with inline comment",
			content:  "SECRET=\"hunter2\" # TODO rotate\n",
			expected: false,
		},
		{
			// Only a comment (or nothing) may follow the closing quote; any
			// other trailing token is malformed and stays plaintext — the safe
			// direction (worst case is an idempotent re-encrypt).
			name:     "quoted ciphertext followed by non-comment token",
			content:  "SECRET=\"encrypted:abc123\" trailing-junk\n",
			expected: false,
		},
		{
			// A quoted empty placeholder with an inline comment carries no
			// secret, mirroring the bare KEY="" empty-assignment rule.
			name:     "empty quoted assignment with inline comment",
			content:  "EMPTY=\"\" # placeholder\nSECRET=\"encrypted:abc123\"\n",
			expected: true,
		},
	})
}

func TestIsEncryptedSOPS(t *testing.T) {
	runIsEncryptedCases(t, []isEncryptedCase{
		{
			// A fully SOPS-encrypted dotenv file: ciphertext values plus the
			// plaintext metadata trailer SOPS always writes. The metadata keys
			// are bookkeeping, not secrets (mirrors the CLI, see #416).
			name: "fully encrypted SOPS dotenv file with metadata trailer",
			content: "DATABASE_URL=\"ENC[AES256_GCM,data:abc,iv:def,tag:ghi,type:str]\"\n" +
				"sops_version=3.9.0\n" +
				"sops_lastmodified=2026-01-01T00:00:00Z\n" +
				"sops_mac=ENC[AES256_GCM,data:mac,type:str]\n" +
				"sops_age__list_0__map_recipient=age1example\n",
			expected: true,
		},
		{
			// A user variable that merely starts with sops_ is a real secret,
			// not SOPS bookkeeping: it must keep the file in mixed state.
			name: "sops_-prefixed user variable stays a plaintext secret",
			content: "DATABASE_URL=\"ENC[AES256_GCM,data:abc,type:str]\"\n" +
				"sops_token=AKIA-very-plaintext\n",
			expected: false,
		},
		{
			// SOPS supports AES256_SIV, not only the default AES256_GCM, and its
			// ciphertext also opens with ENC[. Pinning detection to AES256_GCM
			// mislabeled it as plaintext so the guardian re-encrypted forever
			// (#504 review).
			name:     "fully encrypted SOPS file using AES256_SIV",
			content:  "DATABASE_URL=\"ENC[AES256_SIV,data:abc,iv:def,tag:ghi,type:str]\"\n",
			expected: true,
		},
		{
			name:     "fully encrypted SOPS file using AES256_CTR",
			content:  "API_KEY=\"ENC[AES256_CTR,data:xyz,type:str]\"\n",
			expected: true,
		},
	})
}

func TestIsEncryptedMissingFile(t *testing.T) {
	_, err := IsEncrypted("/nonexistent/path/.env")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

func TestIsEnvdriftAvailable(t *testing.T) {
	// This test just ensures the function doesn't panic
	// Result depends on whether envdrift is installed
	available := IsEnvdriftAvailable()
	t.Logf("envdrift available: %v", available)
}

// writeFakeExe writes an executable shell script named name into dir.
func writeFakeExe(t *testing.T, dir, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-exe shell script not supported on windows")
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}
	return p
}

// TestBuildEncryptCommand_PythonUsesModuleFlag is the #348 G1 regression: when
// findEnvdrift resolves to a python interpreter, buildEncryptCommand must emit
// `python -m envdrift encrypt <file>`, not `python encrypt <file>`.
func TestBuildEncryptCommand_PythonUsesModuleFlag(t *testing.T) {
	dir := t.TempDir()
	// Fake python that succeeds only for `-m envdrift --version` so findEnvdrift
	// selects the python fallback path.
	writeFakeExe(t, dir, "python", `
case "$1 $2 $3" in
  "-m envdrift --version") echo "envdrift 10.0.0"; exit 0 ;;
esac
exit 1
`)
	// PATH contains ONLY our temp dir: no real `envdrift`, no real `python3`.
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		t.Fatalf("buildEncryptCommand: %v", err)
	}

	if got := filepath.Base(cmd.Path); !strings.Contains(got, "python") {
		t.Fatalf("expected python interpreter, got cmd.Path=%q", cmd.Path)
	}
	joined := strings.Join(cmd.Args, " ")
	if !strings.Contains(joined, "-m envdrift") {
		t.Errorf("python invocation missing `-m envdrift`: %v", cmd.Args)
	}
	// Tail must be `... -m envdrift encrypt .env`: `encrypt` is the CLI's
	// per-file path (positional ENV_FILE); `lock` rejects positionals (#481).
	tail := cmd.Args[len(cmd.Args)-4:]
	want := []string{"-m", "envdrift", "encrypt", ".env"}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("args tail = %v, want %v (full: %v)", tail, want, cmd.Args)
			break
		}
	}
}

// TestBuildEncryptCommand_BinaryNoModuleFlag asserts that a standalone envdrift
// binary is invoked directly as `envdrift encrypt <file>` (no `-m envdrift`).
func TestBuildEncryptCommand_BinaryNoModuleFlag(t *testing.T) {
	dir := t.TempDir()
	bin := writeFakeExe(t, dir, "envdrift", `exit 0`)
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		t.Fatalf("buildEncryptCommand: %v", err)
	}

	if cmd.Path != bin {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, bin)
	}
	wantArgs := []string{bin, "encrypt", ".env"}
	if len(cmd.Args) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", cmd.Args, wantArgs)
	}
	for i := range wantArgs {
		if cmd.Args[i] != wantArgs[i] {
			t.Errorf("args = %v, want %v", cmd.Args, wantArgs)
			break
		}
	}
}

// findRealEnvdrift returns the path of a real envdrift CLI, skipping the test
// when none is on PATH (e.g. the cross-OS Go CI matrix, which has no Python).
func findRealEnvdrift(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("envdrift")
	if err != nil {
		t.Skip("envdrift CLI not on PATH; skipping real-CLI test")
	}
	return p
}

// ansiEscapes matches the CSI/OSC escape sequences Rich may emit in help text.
var ansiEscapes = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07`)

// TestBuildEncryptCommand_MatchesRealCLIContract validates the argv that
// buildEncryptCommand emits against the REAL CLI contract, not a hardcoded
// expectation: the chosen subcommand's --help must document a positional
// ENV_FILE argument. The pre-#481 agent ran `envdrift lock <file>`, but `lock`
// takes no positional — every invocation exited 2 ("Got unexpected extra
// argument(s)") and no agent user ever got a file encrypted. If a future CLI
// release drops the positional file argument from the subcommand the agent
// uses, this test breaks loudly instead of the agent failing silently.
func TestBuildEncryptCommand_MatchesRealCLIContract(t *testing.T) {
	bin := findRealEnvdrift(t)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		t.Fatalf("buildEncryptCommand: %v", err)
	}
	// envdrift is on PATH, so the direct-binary form must be chosen:
	// [<envdrift> <subcommand> <file>].
	if len(cmd.Args) != 3 {
		t.Fatalf("expected [envdrift <subcommand> <file>], got %v", cmd.Args)
	}
	subcommand := cmd.Args[1]

	help := exec.Command(bin, subcommand, "--help")
	// Force un-colorized help so the contract assertion is not ANSI-dependent.
	help.Env = append(os.Environ(), "NO_COLOR=1", "FORCE_COLOR=0", "TERM=dumb", "COLUMNS=200")
	out, err := help.CombinedOutput()
	if err != nil {
		t.Fatalf("`envdrift %s --help` failed: %v\n%s", subcommand, err, out)
	}

	plain := ansiEscapes.ReplaceAllString(string(out), "")
	if !strings.Contains(plain, "ENV_FILE") {
		t.Errorf("`envdrift %s` does not accept a positional ENV_FILE argument — "+
			"the agent's encrypt argv violates the real CLI contract (#481).\n--help output:\n%s",
			subcommand, plain)
	}
}

// TestEncryptEndToEnd_RealCLI drives the agent's encrypt step end-to-end
// against the real `envdrift` binary: a plaintext .env must come back fully
// encrypted (IsEncrypted == true). On the pre-#481 argv (`envdrift lock
// <file>`) the CLI exits 2 and the file stays plaintext. Skips when envdrift
// or its dotenvx backend is unavailable.
func TestEncryptEndToEnd_RealCLI(t *testing.T) {
	findRealEnvdrift(t)
	if _, err := exec.LookPath("dotenvx"); err != nil {
		t.Skip("dotenvx not on PATH; skipping end-to-end encrypt test")
	}

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=plaintext-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptSilent(envPath); err != nil {
		t.Fatalf("EncryptSilent(%q) failed against the real CLI: %v\nretry output:\n%s",
			envPath, err, captureEncryptOutput(envPath))
	}

	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "encrypted:") {
		t.Fatalf("file was not encrypted; content:\n%s", content)
	}

	encrypted, err := IsEncrypted(envPath)
	if err != nil {
		t.Fatalf("IsEncrypted: %v", err)
	}
	if !encrypted {
		t.Errorf("IsEncrypted = false after a successful real encrypt; content:\n%s", content)
	}
}

// captureEncryptOutput re-runs the encrypt command with combined output captured
// for diagnostics (EncryptSilent discards it). Best-effort: returns nil bytes if
// the command cannot even be built.
func captureEncryptOutput(envPath string) []byte {
	cmd, err := buildEncryptCommand(envPath)
	if err != nil {
		return nil
	}
	out, _ := cmd.CombinedOutput()
	return out
}

// TestEncryptSilentContext_KillsHungSubprocess is the encrypt-package half of
// the #494 wedge fix: a hung `envdrift encrypt` subprocess must be killed when
// the context expires instead of blocking the caller until the child exits
// (pre-fix EncryptSilent used exec.Command with no context or timeout). A real
// subprocess is used at the process boundary: a fake envdrift that busy-waits
// forever until the context kills it.
//
// The fake hangs with a self-contained shell loop rather than `sleep`: with the
// restricted PATH (only the fake's dir), `sleep` is not resolvable, so a
// `sleep 30` fake would exit immediately with "sleep: not found" and the test
// would pass WITHOUT ever exercising the context kill (a false positive). The
// `while :; do :; done` loop needs only shell builtins, so it truly blocks.
func TestEncryptSilentContext_KillsHungSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping subprocess test in short mode")
	}

	dir := t.TempDir()
	writeFakeExe(t, dir, "envdrift", `while :; do :; done`)
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	const deadline = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	err := EncryptSilentContext(ctx, envPath)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("EncryptSilentContext must report an error when the context kills the subprocess")
	}
	// Ran until (at least roughly) the deadline: guards against the earlier
	// false positive where the fake exited instantly and the timeout path was
	// never taken. The kill cannot precede the deadline, so elapsed >= deadline/2
	// proves the subprocess actually hung.
	if elapsed < deadline/2 {
		t.Fatalf("EncryptSilentContext returned in %v, before the %v deadline; the fake did not actually hang", elapsed, deadline)
	}
	// ...but was killed promptly at the deadline, not blocked for the full run.
	if elapsed > 5*time.Second {
		t.Fatalf("EncryptSilentContext blocked %v on a hung subprocess; the context must kill it (#494)", elapsed)
	}
}

// TestFindEnvdrift_ContextBoundsVersionProbe is the discovery half of the #494
// wedge fix: findEnvdrift's `python -m envdrift --version` probe must be bounded
// by the context too, or a hung python interpreter stalls discovery unbounded
// even though the final encrypt call is context-bounded. With no `envdrift` on
// PATH, discovery falls through to a fake python3 that busy-waits forever; the
// context must kill the probe rather than let findEnvdrift block.
func TestFindEnvdrift_ContextBoundsVersionProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping subprocess test in short mode")
	}

	dir := t.TempDir()
	// Only a hanging python3 on PATH: no real envdrift/python can leak in.
	writeFakeExe(t, dir, "python3", `while :; do :; done`)
	t.Setenv("PATH", dir)

	const deadline = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	_, _, err := findEnvdrift(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("findEnvdrift must fail when the version probe is killed by the context")
	}
	if elapsed < deadline/2 {
		t.Fatalf("findEnvdrift returned in %v, before the %v deadline; the probe did not actually run", elapsed, deadline)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("findEnvdrift blocked %v; the context must bound the version probe (#494)", elapsed)
	}
}

// TestEncryptSilentContext_SucceedsWithinDeadline pins the happy path: a fast
// subprocess under a generous deadline completes without error.
func TestEncryptSilentContext_SucceedsWithinDeadline(t *testing.T) {
	dir := t.TempDir()
	writeFakeExe(t, dir, "envdrift", `exit 0`)
	t.Setenv("PATH", dir)

	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := EncryptSilentContext(ctx, envPath); err != nil {
		t.Fatalf("EncryptSilentContext: %v", err)
	}
}
