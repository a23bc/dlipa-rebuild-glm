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
func (s *Signer) StoreSmoke() (string, error) {
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

	// Read the bundle here rather than through the signer copy. On device the
	// signer field was empty while the machine built from the same load mapped
	// the frameworks fine, so the field is the wrong thing to trust.
	// assets.Load is memoised, so this costs a map lookup.
	bundle, err := assets.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("store smoke: load assets: %w", err)
	}

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
	imageSum := sha256.Sum256(image)
	magic := image
	if len(magic) > 8 {
		magic = magic[:8]
	}
	fmt.Fprintf(os.Stderr, "[SAP] store smoke: AMS %d bytes sha256 %x magic %x\n", len(image), imageSum, magic)

	opened := time.Now()

	runtime, err := emulator.OpenWithEngine(ctx, engine, s.bundle.AppleMediaServices, data)
	if err != nil {
		return "", fmt.Errorf("store smoke: open runtime after %s: %w",
			time.Since(opened).Round(time.Millisecond), err)
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
