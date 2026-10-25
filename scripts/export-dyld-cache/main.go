// Command export-dyld-cache dumps the pinned dyld shared cache to disk so
// profilegen can be run with -cache.
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
	flag.Parse()

	if *prefix == "" {
		return fmt.Errorf("-prefix is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return assets.WriteSharedCache(ctx, *prefix)
}
