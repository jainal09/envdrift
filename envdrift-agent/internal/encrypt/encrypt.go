// Package encrypt handles dotenvx encryption integration.
package encrypt

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

// IsEncrypted checks if a .env file is already encrypted.
// Looks for "encrypted:" marker in file contents.
func IsEncrypted(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "encrypted:") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// Encrypt encrypts a .env file using dotenvx.
// Returns error if dotenvx is not available or encryption fails.
func Encrypt(path string) error {
	dotenvx, err := findDotenvx()
	if err != nil {
		return err
	}

	cmd := exec.Command(dotenvx, "encrypt", "-f", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// EncryptSilent encrypts without output
func EncryptSilent(path string) error {
	dotenvx, err := findDotenvx()
	if err != nil {
		return err
	}

	cmd := exec.Command(dotenvx, "encrypt", "-f", path)
	return cmd.Run()
}

// IsDotenvxAvailable checks if dotenvx is installed
func IsDotenvxAvailable() bool {
	_, err := findDotenvx()
	return err == nil
}

// findDotenvx locates the dotenvx binary
func findDotenvx() (string, error) {
	// Check common locations
	candidates := []string{
		"dotenvx",                   // In PATH
		"/usr/local/bin/dotenvx",    // Homebrew
		"/opt/homebrew/bin/dotenvx", // Homebrew ARM Mac
	}

	// Also check npx
	if npx, err := exec.LookPath("npx"); err == nil {
		// Verify npx can run dotenvx
		cmd := exec.Command(npx, "dotenvx", "--version")
		if cmd.Run() == nil {
			return npx, nil // Will need to be called as "npx dotenvx"
		}
	}

	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
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
	return path
}
