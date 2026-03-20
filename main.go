// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/k8shell-io/common/pkg/logger"
	"github.com/k8shell-io/identity/internal/server"
)

var (
	VERSION = "0.0.0"
	COMMIT  = "0000000"
)

// Options holds the parsed command-line options.
type Options struct {
	ConfigPath  string
	LogText     bool
	ShowVersion bool
}

// getOptions parses command-line flags and returns the resulting Options.
// When -v is passed it prints version information and exits immediately.
func getOptions(version string, commitID string) (*Options, error) {
	options := &Options{
		ConfigPath:  "config/config.yaml",
		LogText:     false,
		ShowVersion: false,
	}

	flag.StringVar(&options.ConfigPath, "config", options.ConfigPath, "Path to the configuration file")
	flag.BoolVar(&options.LogText, "logtext", options.LogText, "Log in text format (default: JSON)")
	flag.BoolVar(&options.ShowVersion, "v", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  identity [options]\n")
		fmt.Fprint(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprint(os.Stderr, "  --config <file>    Configuration file\n")
		fmt.Fprint(os.Stderr, "  --logtext          Log in text format (default: JSON)\n")
		fmt.Fprint(os.Stderr, "  -v                 Show version and exit\n")
	}

	flag.Parse()
	if options.ShowVersion {
		fmt.Printf("identity version: %s (commit: %s)\n", version, commitID)
		os.Exit(0)
	}

	return options, nil
}

// main is the entry point for the identity service.
func main() {
	opts, err := getOptions(VERSION, COMMIT)
	if err != nil {
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	log.JsonLogger = !opts.LogText
	log := log.NewLogger("server")

	server, err := server.NewServer(opts.ConfigPath)
	if err != nil {
		log.Error().Msgf("Error starting server: %v\n", err)
		return
	}

	err = server.Serve()
	if err != nil {
		log.Error().Msgf("Error serving server: %v\n", err)
	}
}
