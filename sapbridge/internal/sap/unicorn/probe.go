package unicorn

import (
	"context"
	"fmt"
	"os"
)

// ProbeEngine runs the smallest possible engine life cycle: open, set the
// translation buffer size, one mem_map to force UC_INIT, close.
//
// It exists because the full open fails intermittently with "Could not allocate
// dynamic translator buffer" and every explanation offered so far has been wrong.
// This isolates the question: if the probe fails too, the problem is the engine
// and the platform, not the images, the profile, or whatever else the app was
// doing at the time. If it succeeds repeatedly while the full open still fails,
// the difference is in what runs around the open.
func ProbeEngine(ctx context.Context) error {
	engine, err := New(ctx)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}

	defer func() { _ = engine.Close() }()

	fmt.Fprintf(os.Stderr, "[SAP] probe: uc_open ok, buffer=%d, rss=%dMB\n",
		tcgBufferSizeIOS, maxResidentMB())

	// The first map is what triggers UC_INIT, which is where code_gen_alloc runs
	// and where the app dies. A page is enough.
	if err := engine.err(engine.api.memMap(engine.handle, 0x100000000, 4096, 7)); err != nil {
		return fmt.Errorf("probe: mem_map: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[SAP] probe: mem_map ok, rss=%dMB\n", maxResidentMB())

	return nil
}
