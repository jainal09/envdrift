// Package encrypt handles encryption via envdrift lock.
// Requires envdrift CLI to be installed (pip install envdrift).
package encrypt

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrEnvdriftNotFound is returned when envdrift CLI is not installed.
var ErrEnvdriftNotFound = errors.New("envdrift not found. Install it: pip install envdrift")

// IsEncrypted checks if a .env file is already encrypted.
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "encrypted:") {
			return true, nil
		}
	}

	return false, scanner.Err()
}

// Encrypt encrypts a .env file using envdrift lock.
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

// buildEncryptCommand builds the envdrift lock command.
func buildEncryptCommand(path string) (*exec.Cmd, error) {
	dir := filepath.Dir(path)
	fileName := filepath.Base(path)

	envdrift, err := findEnvdrift()
	if err != nil {
		return nil, ErrEnvdriftNotFound
	}

	cmd := exec.Command(envdrift, "lock", fileName)
	cmd.Dir = dir
	return cmd, nil
}

// findEnvdrift locates the envdrift executable.
func findEnvdrift() (string, error) {
	// Check if envdrift is in PATH
	if path, err := exec.LookPath("envdrift"); err == nil {
		return path, nil
	}

	// Try python3 -m envdrift
	if python, err := exec.LookPath("python3"); err == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return python, nil // Will need special handling
		}
	}

	// Try python -m envdrift
	if python, err := exec.LookPath("python"); err == nil {
		cmd := exec.Command(python, "-m", "envdrift", "--version")
		if cmd.Run() == nil {
			return python, nil
		}
	}

	return "", exec.ErrNotFound
}
