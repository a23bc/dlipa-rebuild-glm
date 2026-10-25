// Command export-dyld-cache dumps the pinned shared cache and the feature-flag
// plists profilegen reads, so profilegen can run with -cache.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	prefix := flag.String("prefix", "", "output path prefix for the shared-cache members")
	systemDir := flag.String("system-dir", "", "directory for the FeatureFlags plists")
	flag.Parse()

	if *prefix == "" {
		return fmt.Errorf("-prefix is required")
	}

	if *systemDir == "" {
		return fmt.Errorf("-system-dir is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return assets.WriteCache(ctx, *prefix, *systemDir)
}
