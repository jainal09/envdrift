// Package encrypt tests
package encrypt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected bool
	}{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
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
