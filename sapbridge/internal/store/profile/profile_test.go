package profile

import (
	"context"
	"testing"
)

// The three decoded sizes are the whole point of this package: if they match,
// the generated source, the zstd frames and the digests are all intact. If they
// do not, nothing built on top of the profile can be trusted, so this is the
// cheapest possible gate before touching the emulator.
func TestLoadDecodesThePinnedProfile(t *testing.T) {
	data, err := Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string]struct {
		got  int
		size int
	}{
		"metadata": {len(data.Metadata), 4807917},
		"pages":    {len(data.Pages), 20893696},
		"plugin":   {len(data.Plugin), 138088},
	}

	for name, w := range want {
		if w.got != w.size {
			t.Errorf("%s: decoded %d bytes, the pinned profile says %d", name, w.got, w.size)
		}
	}

	t.Logf("metadata %d, pages %d, plugin %d bytes",
		len(data.Metadata), len(data.Pages), len(data.Plugin))
}

// Load is documented as once per process; the second call must return the same
// values rather than reading the generated source again.
func TestLoadIsMemoised(t *testing.T) {
	first, err := Load(context.Background())
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}

	second, err := Load(context.Background())
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}

	if len(first.Pages) != len(second.Pages) || &first.Pages[0] != &second.Pages[0] {
		t.Error("second Load did not return the memoised data")
	}
}
