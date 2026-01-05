// Package main provides the entry point for envdrift-agent.
package main

import (
	"os"

	"github.com/jainal09/envdrift-agent/internal/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
