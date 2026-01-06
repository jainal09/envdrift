// Package encrypt handles encryption integration.
// Prefers envdrift CLI (respects envdrift.toml, vault, ephemeral keys),
// falls back to dotenvx if envdrift is not available.
package encrypt

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const npxMarker = "npx:dotenvx"

// IsEncrypted checks if a .env file is already encrypted.
func IsEncrypted(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Check for encrypted marker in actual values
		if strings.Contains(strings.ToLower(line), "encrypted:") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// Encrypt encrypts a .env file, preferring envdrift lock over dotenvx.
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
	_, err := findEnvdrift()
	return err == nil
}

// IsDotenvxAvailable checks if dotenvx is available.
func IsDotenvxAvailable() bool {
	_, err := findDotenvx()
	return err == nil
}

// buildEncryptCommand builds the encryption command.
// Tries envdrift lock first, falls back to dotenvx encrypt.
func buildEncryptCommand(path string) (*exec.Cmd, error) {
	dir := filepath.Dir(path)
	fileName := filepath.Base(path)

	// Try envdrift first (respects envdrift.toml, vault, ephemeral keys)
	if envdrift, err := findEnvdrift(); err == nil {
		cmd := exec.Command(envdrift, "lock", fileName)
		cmd.Dir = dir
		return cmd, nil
	}

	// Fallback to dotenvx
	dotenvx, err := findDotenvx()
	if err != nil {
		return nil, err
	}

	// Handle npx case
	if dotenvx == npxMarker {
		cmd := exec.Command("npx", "-y", "@dotenvx/dotenvx", "encrypt", "-f", path)
		cmd.Dir = dir
		return cmd, nil
	}

	cmd := exec.Command(dotenvx, "encrypt", "-f", path)
	cmd.Dir = dir
	return cmd, nil
}

// findEnvdrift locates the envdrift executable.
func findEnvdrift() (string, error) {
	candidates := []string{
		"envdrift", // In PATH
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	// Try python -m envdrift
	if python, err := exec.LookPath("python3"); err == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return "python3 -m envdrift", nil
		}
	}
	if python, err := exec.LookPath("python"); err == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return "python -m envdrift", nil
		}
	}

	return "", exec.ErrNotFound
}

// findDotenvx locates the dotenvx executable.
func findDotenvx() (string, error) {
	candidates := []string{
		"dotenvx",
		"/usr/local/bin/dotenvx",
		"/opt/homebrew/bin/dotenvx",
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	// Fallback to npx
	if npx, err := exec.LookPath("npx"); err == nil {
		cmd := exec.Command(npx, "dotenvx", "--version")
		if cmd.Run() == nil {
			return npxMarker, nil
		}
	}

	return "", exec.ErrNotFound
}

// GetDotenvxPath returns the path to dotenvx (for backwards compatibility).
func GetDotenvxPath() string {
	path, err := findDotenvx()
	if err != nil {
		return ""
	}
	if path == npxMarker {
		return "npx dotenvx"
	}
	return path
}
