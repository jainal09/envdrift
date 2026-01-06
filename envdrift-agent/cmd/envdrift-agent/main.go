// Package main provides the entry point for envdrift-agent.
package main

import (
	"os"

	"github.com/jainal09/envdrift-agent/internal/cmd"
)

// main is the program entry point for envdrift-agent. It runs cmd.Execute and exits with status 1 if that call returns an error.
func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}