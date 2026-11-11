// Command exportassets writes the seven pinned macOS 27 SAP files that this
// repository's own loader accepts, from Apple's restore image, into a
// directory.
//
// It exists so the CI artifact and the device are produced by the same code.
// The job used to run upstream ipatool's extractor instead, which is a four
// file profile: the three identity binaries this command writes came out of
// nothing, and the four that did were checked against digests this repository
// also pins. Two profiles, one artifact -- which is how a green CI upload
// turns into "adid is empty or missing" wherever the staged route is used.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assetsremote"
)

func main() {
	out := flag.String("out", "VendorAssets", "directory to write the seven binaries into")
	timeout := flag.Duration("timeout", 90*time.Minute, "upper bound for download and extraction")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "exportassets: create output directory:", err)
		os.Exit(1)
	}

	bundle, err := assetsremote.Load(ctx)
	if err != nil {
		// The bytes are the point of this command, so report the spend even
		// when it stops: how far a run got before it failed is the half that
		// decides whether the approach fits anywhere.
		fmt.Fprintln(os.Stderr, "exportassets:", err)
		os.Exit(1)
	}

	if err := assetsremote.WriteBundle(bundle, *out); err != nil {
		fmt.Fprintln(os.Stderr, "exportassets:", err)
		os.Exit(1)
	}

	total := len(bundle.AppleMediaServices) + len(bundle.Commerce) + len(bundle.ADID) +
		len(bundle.CoreFP) + len(bundle.CoreFPICXS) + len(bundle.FairPlayD) +
		len(bundle.FairPlayKext)

	fmt.Printf("exportassets: wrote %d bytes across 7 files to %s\n", total, *out)
}
