package emulator

import (
	"context"
	"testing"

	storeprofile "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

func TestPreparedPagesAreNotEmpty(t *testing.T) {
	data, err := storeprofile.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	pages, err := PreparedPages(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("prepared pages: %v", err)
	}

	t.Logf("metadata=%d bytes pagesBlob=%d bytes preparedPages=%d", len(data.Metadata), len(data.Pages), len(pages))

	if len(pages) == 0 {
		t.Fatalf("PreparedPages returned no pages")
	}
}
