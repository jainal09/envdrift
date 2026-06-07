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
		// An encrypted entry has a value that starts with "encrypted:"
		// (e.g. KEY="encrypted:..."). Anchor to the value so a plaintext
		// substring like `NOTE=not encrypted: yet` is not a false positive (#348 G6).
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		value := strings.TrimSpace(line[eq+1:])
		value = strings.Trim(value, `"'`)
		if strings.HasPrefix(strings.ToLower(value), "encrypted:") {
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
	_, _, err := findEnvdrift()
	return err == nil
}

// buildEncryptCommand builds the envdrift lock command.
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
		cmd = exec.Command(envdrift, "-m", "envdrift", "lock", fileName)
	} else {
		cmd = exec.Command(envdrift, "lock", fileName)
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
