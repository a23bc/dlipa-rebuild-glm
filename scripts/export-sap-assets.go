// Exports the four pinned macOS 27 SAP binaries.
//
// Upstream ipatool already knows how to pull them: assets.Load reads its cache
// and, when the cache is empty, resolves them from the pinned restore image
// (assets.go: macOSRestoreURL = UniversalMac_27.0.1_26A434_Restore.ipsw) and
// writes them back into the cache. Re-implementing the AEA/APFS/dyld-cache
// extraction here would be a second, worse copy of code that already exists.
//
// So this program does three things: call Load, then copy the four files out of
// the cache directory Load just populated, then let the workflow verify their
// digests.
//
// It has to live inside the ipatool module to reach internal/sap/assets, which
// is why the workflow copies it into that checkout before running it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// Kept in sync with assets.go: assetCacheDirectory. Not exported there.
const cacheDirectoryName = "apple-assets-macos-27-26A434-arm64-v1"

var requiredFiles = []string{"AppleMediaServices", "commerce", "CoreFP", "CoreFP.icxs"}

func main() {
	out := flag.String("out", "VendorAssets", "directory to write the binaries into")
	timeout := flag.Duration("timeout", 90*time.Minute, "upper bound for download and extraction")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	fmt.Println("==> resolving macOS 27 assets (this downloads from Apple, several GB)")
	if _, err := assets.Load(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "load assets: %v\n", err)
		os.Exit(1)
	}

	root, err := os.UserCacheDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "user cache dir: %v\n", err)
		os.Exit(1)
	}
	source := filepath.Join(root, "ipatool", "sap", cacheDirectoryName)

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create output: %v\n", err)
		os.Exit(1)
	}

	for _, name := range requiredFiles {
		from := filepath.Join(source, name)
		to := filepath.Join(*out, name)
		if err := copyFile(from, to); err != nil {
			fmt.Fprintf(os.Stderr, "copy %s: %v\n", name, err)
			os.Exit(1)
		}
		fmt.Printf("  ok %s\n", name)
	}
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(to)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
