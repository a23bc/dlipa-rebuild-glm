package sap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStoredKBSyncNameCarriesTheFormatVersion pins the mechanism that replaced the
// launch-time sweep keyed on CFBundleShortVersionString. A blob is read back
// because its stored name says this build can use it; change what a blob has to
// be, move the version in that name, and every old one retires by missing.
//
// The sweep this replaces cost 32 s of full-core work per account at the first
// download of every new build, and it fired on shipping a build, which is not
// the same event as the guest's assumptions changing.
func TestStoredKBSyncNameCarriesTheFormatVersion(t *testing.T) {
	dir := t.TempDir()

	// os.UserCacheDir consults a different variable per platform, and all three
	// are set so the test cannot reach a real device cache on any of them.
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("LOCALAPPDATA", dir)
	t.Setenv("HOME", dir)

	const account = uint64(333)

	// The name is the whole mechanism: a path that does not carry it would let two
	// incompatible builds read each other's blobs and call that a cache hit.
	if !strings.Contains(kbsyncCachePath(account), kbsyncFormatVersion+"-") {
		t.Fatalf("stored blobs do not carry the format version: %s", kbsyncCachePath(account))
	}

	if kbsyncCachePath(account) == legacyKBSyncPath(account) {
		t.Fatalf("the versioned and un-versioned names are the same file: %s",
			kbsyncCachePath(account))
	}

	if err := os.MkdirAll(filepath.Dir(legacyKBSyncPath(account)), 0o700); err != nil {
		t.Fatalf("prepare the cache directory: %v", err)
	}

	if err := os.WriteFile(legacyKBSyncPath(account), []byte("old build's blob"), 0o600); err != nil {
		t.Fatalf("write the un-versioned blob: %v", err)
	}

	signer := &Signer{}

	// An un-versioned file is a miss. Serving it would be the exact thing the
	// version was introduced to make impossible.
	if blob, ok := signer.cachedKBSync(account); ok {
		t.Fatalf("an un-versioned blob was served to this build: %q", blob)
	}

	// And it is removed on the way past, because those bytes are credential
	// material nothing reads any more and the sweep that used to delete them at
	// upgrade is gone. A miss that leaves the file is the difference between
	// retiring an old blob and keeping it on disk indefinitely.
	if _, err := os.Stat(legacyKBSyncPath(account)); !os.IsNotExist(err) {
		t.Fatalf("the un-versioned blob survived a miss: %v", err)
	}

	if err := os.WriteFile(kbsyncCachePath(account), []byte("this build's blob"), 0o600); err != nil {
		t.Fatalf("write the versioned blob: %v", err)
	}

	if blob, ok := signer.cachedKBSync(account); !ok || string(blob) != "this build's blob" {
		t.Fatalf("the versioned blob was not read back: %q, ok=%v", blob, ok)
	}
}
