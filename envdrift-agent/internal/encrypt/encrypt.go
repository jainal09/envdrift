// Package encrypt handles dotenvx encryption integration.
package encrypt

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

const npxMarker = "npx:dotenvx"

// IsEncrypted checks if a .env file is already encrypted.
// Looks for "encrypted:" marker in non-comment lines (dotenvx format).
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

// Encrypt encrypts a .env file using dotenvx.
// Returns error if dotenvx is not available or encryption fails.
func Encrypt(path string) error {
	cmd, err := buildDotenvxCommand("encrypt", "-f", path)
	if err != nil {
		return err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// EncryptSilent encrypts without output
func EncryptSilent(path string) error {
	cmd, err := buildDotenvxCommand("encrypt", "-f", path)
	if err != nil {
		return err
	}
	return cmd.Run()
}

// IsDotenvxAvailable checks if dotenvx is installed
func IsDotenvxAvailable() bool {
	_, err := findDotenvx()
	return err == nil
}

// buildDotenvxCommand constructs the correct command for dotenvx
func buildDotenvxCommand(args ...string) (*exec.Cmd, error) {
	dotenvx, err := findDotenvx()
	if err != nil {
		return nil, err
	}

	// Handle npx case
	if dotenvx == npxMarker {
		fullArgs := append([]string{"dotenvx"}, args...)
		return exec.Command("npx", fullArgs...), nil
	}

	return exec.Command(dotenvx, args...), nil
}

// findDotenvx locates the dotenvx binary
func findDotenvx() (string, error) {
	// Check common locations first
	candidates := []string{
		"dotenvx",                   // In PATH
		"/usr/local/bin/dotenvx",    // Homebrew
		"/opt/homebrew/bin/dotenvx", // Homebrew ARM Mac
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	// Fallback to npx
	if npx, err := exec.LookPath("npx"); err == nil {
		// Verify npx can run dotenvx
		cmd := exec.Command(npx, "dotenvx", "--version")
		if cmd.Run() == nil {
			return npxMarker, nil // Special marker for npx
		}
	}

	return "", exec.ErrNotFound
}

// GetDotenvxPath returns path to dotenvx or empty string if not found
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
