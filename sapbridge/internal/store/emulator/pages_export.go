package emulator

import (
	"context"
	"fmt"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile/format"
)

// PreparedPages decodes a profile metadata blob and returns its page table.
//
// The metadata is not plain JSON: prepareMetadata unwraps it into the structures
// the runtime needs. Callers outside this package (the cache-page exporter) need
// the same decoding, so this exposes just the page table rather than the whole
// prepared set.
func PreparedPages(ctx context.Context, raw []byte) ([]format.Page, error) {
	meta, err := prepareMetadata(raw)
	if err != nil {
		return nil, fmt.Errorf("prepare metadata: %w", err)
	}

	return meta.profile.Pages, nil
}
