package sap

// Store runtime smoke test.
//
// This answers one question and nothing else: can the Store runtime be built on
// the guest this process already has, and how long does it take? Both numbers
// are measured rather than inferred, because the answer decides whether the
// emulator path is viable on this device at all.
//
// It deliberately stops before any Objective-C message send. Opening the runtime
// maps the profile pages and builds the class tables, which is the expensive and
// failure-prone half; if this cannot finish, nothing built on top of it can. The
// message send is the next step and is worth measuring separately so a slow
// result can be attributed to one half or the other.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// StoreSmoke opens the Store runtime on the signer's machine and reports timings.
func (s *Signer) StoreSmoke(bundle assets.Bundle) (string, error) {
	if s == nil || s.machine == nil {
		return "", fmt.Errorf("store smoke: no machine")
	}

	engine := s.machine.Engine()
	if engine == nil {
		return "", fmt.Errorf("store smoke: machine has no engine")
	}

	// A background context, not s.context: that field is the SAP session value
	// (a uint64), not a Go context, and the name collision is easy to miss.
	ctx := context.Background()


	started := time.Now()

	data, err := profile.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("store smoke: load profile: %w", err)
	}

	loaded := time.Since(started)

	// Print what is actually being handed to the runtime, not what we believe is
	// there. The pinned digest lives in runtime.go and the loader has its own copy
	// in assets.go; if the two disagree the only way to tell which slice is wrong
	// is to look at the bytes in the app.
	image := bundle.AppleMediaServices

	// Fail with the number in the message. The slicer's own error says only
	// "too short to hold a Mach-O magic", which leaves open whether the bundle
	// was empty or the file was tiny; naming the length removes that doubt.
	if len(image) < 4 {
		return "", fmt.Errorf("store smoke: bundle gave %d bytes for AppleMediaServices (commerce %d, CoreFP %d, icxs %d)",
			len(image), len(bundle.Commerce), len(bundle.CoreFP), len(bundle.CoreFPICXS))
	}
	imageSum := sha256.Sum256(image)
	magic := image
	if len(magic) > 8 {
		magic = magic[:8]
	}
	fmt.Fprintf(os.Stderr, "[SAP] store smoke: AMS %d bytes sha256 %x magic %x\n", len(image), imageSum, magic)

	opened := time.Now()

	runtime, err := emulator.OpenWithEngine(ctx, engine, image, data)
	if err != nil {
		// The sizes go into the error string on purpose. Everything printed to
		// stderr only replays on the next launch, so a diagnostic written there
		// is always one press behind. The error reaches AppLog immediately.
		return "", fmt.Errorf("store smoke: open runtime after %s: %w (image=%d bytes, plugin=%d bytes)",
			time.Since(opened).Round(time.Millisecond), err, len(image), len(data.Plugin))
	}

	openDuration := time.Since(opened)

	// Closing releases guest-side objects but leaves the shared engine running,
	// which is the behaviour OpenWithEngine exists to provide.
	closeStart := time.Now()

	if err := runtime.Close(); err != nil {
		return "", fmt.Errorf("store smoke: close runtime: %w", err)
	}

	closed := time.Since(closeStart)

	return fmt.Sprintf(
		"profile %d MB in %s; runtime opened in %s; closed in %s",
		(len(data.Metadata)+len(data.Pages)+len(data.Plugin))/(1<<20),
		loaded.Round(time.Millisecond),
		openDuration.Round(time.Millisecond),
		closed.Round(time.Millisecond),
	), nil
}
