package sap

// Store runtime smoke test.
//
// This answers one question and nothing else: can the Store runtime be built on
// this device, and how long does it take? Both numbers are measured rather than
// inferred, because the answer decides whether the emulator path is viable here.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/emulator"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// StoreSmoke opens the Store runtime and reports how long each half took.
//
// It runs on a fresh guest rather than on the SAP machine's engine. The two want
// the same addresses: the machine has AppleMediaServices mapped around
// 0x1a0000000, and the profile's prepared pages live in that same range, so
// sharing one address space made the page mapping fail with UC_ERR_MAP. A second
// guest costs memory, but it removes the requirement that two independent
// layouts agree -- which is the point of this build.
func (s *Signer) StoreSmoke(image []byte) (string, error) {
	if s == nil || s.machine == nil {
		return "", fmt.Errorf("store smoke: no machine")
	}

	if len(image) < 4 {
		return "", fmt.Errorf("store smoke: got %d bytes for AppleMediaServices", len(image))
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

	imageSum := sha256.Sum256(image)

	magic := image
	if len(magic) > 8 {
		magic = magic[:8]
	}

	fmt.Fprintf(os.Stderr, "[SAP] store smoke: AMS %d bytes sha256 %x magic %x\n", len(image), imageSum, magic)

	opened := time.Now()

	// Share the SAP machine's engine. A second engine cannot be created in this
	// process at all: TCG's translator buffer is initialised once per process,
	// so the second uc_open fails with "Could not allocate dynamic translator
	// buffer". Sharing is not a memory optimisation here, it is the only option.
	engine := s.machine.Engine()
	if engine == nil {
		return "", fmt.Errorf("store smoke: machine has no engine")
	}

	runtime, err := emulator.OpenWithEngine(ctx, engine, image, data)
	if err != nil {
		return "", fmt.Errorf("store smoke: open runtime after %s: %w (image=%d bytes, plugin=%d bytes)",
			time.Since(opened).Round(time.Millisecond), err, len(image), len(data.Plugin))
	}

	openDuration := time.Since(opened)

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
