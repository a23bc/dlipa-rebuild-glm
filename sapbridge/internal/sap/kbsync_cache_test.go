package sap

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCachedKBSyncNeverServesAnotherAccountsSlot pins the one thing the account
// switch rests on: the blob belongs to the account, not to whichever session is
// holding the machine. The reuse path used to answer from the slot without
// asking whose blob it was, so after a request for a second account the first
// account's next download went out carrying the second account's kbsync and came
// back as `ent/download (encoder) HTTP 500, 0 bytes` with an empty body.
func TestCachedKBSyncNeverServesAnotherAccountsSlot(t *testing.T) {
	dir := t.TempDir()

	// os.UserCacheDir consults a different variable per platform, and all three
	// are set so the test cannot reach a real device cache on any of them.
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("HOME", dir)

	const first, second = uint64(111), uint64(222)
	signer := &Signer{kbsyncBlob: []byte("first account"), kbsyncDSID: first}

	if blob, ok := signer.cachedKBSync(first); !ok || string(blob) != "first account" {
		t.Fatalf("the slot's own account did not get its blob: %q, ok=%v", blob, ok)
	}

	if blob, ok := signer.cachedKBSync(second); ok {
		t.Fatalf("DSID %d was served the slot of DSID %d: %q", second, first, blob)
	}

	stored := []byte("second account blob")
	path := kbsyncCachePath(second)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("prepare the cache directory: %v", err)
	}

	if err := os.WriteFile(path, stored, 0o600); err != nil {
		t.Fatalf("write the stored blob: %v", err)
	}

	if blob, ok := signer.cachedKBSync(second); !ok || string(blob) != string(stored) {
		t.Fatalf("the disk blob for DSID %d was not read back: %q, ok=%v", second, blob, ok)
	}

	// The slot has moved on and the first account has no file of its own here, so
	// its next request must report a miss rather than reuse what it finds in
	// memory. That miss is the refusal the download path turns into a message.
	if blob, ok := signer.cachedKBSync(first); ok {
		t.Fatalf("DSID %d was served %q after the slot moved", first, blob)
	}
}
