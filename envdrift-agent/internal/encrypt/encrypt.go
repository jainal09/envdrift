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
// IsEncrypted reports whether the file at path contains an "encrypted:" marker in any non-empty, non-comment line.
// It returns true if such a marker is found. If the file cannot be opened the open error is returned; otherwise it returns false and any scanner error encountered.
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
// Encrypt runs dotenvx to encrypt the dotenv file at the provided path.
// It locates the dotenvx executable (or uses `npx dotenvx` if available), invokes `dotenvx encrypt -f <path>`, streams the command's stdout and stderr to the current process, and returns any error encountered while locating or running the command.
func Encrypt(path string) error {
	cmd, err := buildDotenvxCommand("encrypt", "-f", path)
	if err != nil {
		return err
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// EncryptSilent encrypts the dotenv file at the given path using dotenvx without explicitly attaching the command's stdout or stderr to the current process.
// It returns an error if the dotenvx command cannot be constructed or if executing the command fails.
func EncryptSilent(path string) error {
	cmd, err := buildDotenvxCommand("encrypt", "-f", path)
	if err != nil {
		return err
	}
	return cmd.Run()
}

// IsDotenvxAvailable reports whether a usable dotenvx executable is present on the system.
// It returns true if a dotenvx binary is found or if `npx dotenvx` can be invoked successfully, false otherwise.
func IsDotenvxAvailable() bool {
	_, err := findDotenvx()
	return err == nil
}

// buildDotenvxCommand constructs the appropriate *exec.Cmd for running dotenvx with the provided arguments.
// If the resolver indicates the npx marker, the returned command runs `npx dotenvx ...`.
// Returns an error if locating a suitable dotenvx runner fails.
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

// findDotenvx locates the dotenvx executable.
// It returns the full path to the executable, the special marker `npxMarker` if dotenvx is available via `npx`, or `exec.ErrNotFound` when neither a direct executable nor a usable `npx` invocation is found.
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

// GetDotenvxPath returns the filesystem path to the dotenvx executable, "npx dotenvx"
// if dotenvx is available via npx, or an empty string if no usable dotenvx provider is found.
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