package emulator

import (
	"context"
	"testing"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile"
)

// metadata.go turns the 4.6 MB metadata blob into the lookup tables the bridge
// needs on every message send. Parsing it is pure work -- no guest, no engine --
// so it can be checked here before any of the emulator port is written.
func TestMetadataLoadsFromThePinnedProfile(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	meta, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}

	counts := map[string]int{
		"classes":           len(meta.classes),
		"classNames":        len(meta.classNames),
		"methods":           len(meta.methods),
		"calls":             len(meta.calls),
		"selectors":         len(meta.selectors),
		"selectorAddresses": len(meta.selectorAddresses),
		"objects":           len(meta.objects),
		"entries":           len(meta.entries),
	}

	for name, count := range counts {
		t.Logf("%-18s %d", name, count)
		if count == 0 {
			t.Errorf("%s is empty; the metadata blob parsed into nothing", name)
		}
	}

	// A real StoreKit profile carries several hundred classes and thousands of
	// methods. Ranges, not exact numbers: the point is to catch a parse that
	// silently produced a handful of records.
	if counts["classes"] < 100 {
		t.Errorf("only %d classes; expected hundreds", counts["classes"])
	}

	if counts["methods"] < 1000 {
		t.Errorf("only %d methods; expected thousands", counts["methods"])
	}

	// newRuntime is what the bridge will call per session. It must hand out the
	// same tables without sharing the ones that belong to a single VM.
	runtime := meta.newRuntime()
	if runtime == nil {
		t.Fatal("newRuntime returned nil")
	}

	if len(runtime.classes) != counts["classes"] {
		t.Errorf("newRuntime has %d classes, metadata has %d",
			len(runtime.classes), counts["classes"])
	}

	if len(runtime.methods) != counts["methods"] {
		t.Errorf("newRuntime has %d methods, metadata has %d",
			len(runtime.methods), counts["methods"])
	}
}

// The digest is a cache key, not an integrity check: it exists so a different
// profile cannot silently reuse the previous one's tables. So the behaviour to
// pin down is that the same blob is parsed once and a different one is not
// served from the cache.
func TestMetadataCachesByDigest(t *testing.T) {
	data, err := profile.Load(context.Background())
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}

	first, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("first load: %v", err)
	}

	again, err := cachedMetadata.load(context.Background(), data.Metadata)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}

	if first != again {
		t.Error("the same metadata blob was parsed twice; the digest cache missed")
	}

	// A blob that is not the pinned one must be rejected outright, not parsed
	// into empty tables. Truncation is unambiguous: nothing valid can come of it.
	truncated := data.Metadata[:len(data.Metadata)/2]
	if _, err := cachedMetadata.load(context.Background(), truncated); err == nil {
		t.Error("a truncated metadata blob was accepted")
	}
}
