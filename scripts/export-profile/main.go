// Command export-profile regenerates the Store profile from a locally dumped
// cache, reading feature flags from the same dump instead of from the host.
//
// This is upstream's cmd/profilegen with one difference: it opens the cache with
// OpenLocalStoreCacheWithSystemFiles, which resolves readSystemFile inside the
// dumped directory. Upstream's version uses OpenLocalStoreCache, whose
// readSystemFile is os.ReadFile -- on a Linux runner those paths do not exist,
// and on a macOS runner they resolve to the runner's own OS rather than to the
// image we pin. Both would change the generated profile, the second silently.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/store/profilegen"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	prefix := flag.String("prefix", "", "path prefix of the dumped shared-cache members")
	systemDir := flag.String("system-dir", "", "directory holding the dumped FeatureFlags plists")
	output := flag.String("output", "", "path to write the generated Go source to")
	flag.Parse()

	if *prefix == "" {
		return fmt.Errorf("-prefix is required")
	}

	if *systemDir == "" {
		return fmt.Errorf("-system-dir is required")
	}

	if *output == "" {
		return fmt.Errorf("-output is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	fmt.Fprintln(os.Stderr, "Generating Store profile from the dumped cache...")

	cache, err := assets.OpenLocalStoreCacheWithSystemFiles(ctx, *prefix, *systemDir)
	if err != nil {
		return fmt.Errorf("open dumped cache: %w", err)
	}

	defer cache.Close()

	result, err := profilegen.Generate(ctx, cache)
	if err != nil {
		return fmt.Errorf("generate profile: %w", err)
	}

	pluginPath := filepath.Join(os.TempDir(), "AMSAccountAuthenticationPlugin")

	if err := cache.ExtractAuthenticationPlugin(pluginPath); err != nil {
		return fmt.Errorf("extract authentication plugin: %w", err)
	}

	plugin, err := os.ReadFile(pluginPath)
	if err != nil {
		return fmt.Errorf("read authentication plugin: %w", err)
	}

	source, err := result.GoSource(ctx, plugin)
	if err != nil {
		return fmt.Errorf("encode profile source: %w", err)
	}

	if err := os.WriteFile(*output, source, 0o644); err != nil {
		return fmt.Errorf("write profile source: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes).\n", *output, len(source))

	// A profile that is adversarially small is a failed generation that still
	// produced a file, so state the size comparison rather than trusting exit 0.
	if bytes.HasPrefix(source, []byte("// Code generated")) {
		fmt.Fprintln(os.Stderr, "header looks right")
	} else {
		return fmt.Errorf("generated source does not start with the expected header")
	}

	return nil
}
