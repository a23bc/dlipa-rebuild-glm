package assets

// Dumps everything profilegen needs to run offline.
//
// profilegen takes -cache <prefix>, and OpenLocalStoreCache opens <prefix>+suffix
// for the shared cache. It also reads three FeatureFlags plists through
// readSystemFile -- and OpenLocalStoreCache points that at os.ReadFile, i.e. at
// the host. On a Linux runner the paths do not exist; on a macOS runner they
// resolve to the runner's own OS, which is not the image we pin. Either way the
// feature table in the generated profile would be wrong, and wrong silently.
//
// So the flags are dumped from the same image alongside the cache, and
// OpenLocalStoreCacheWithSystemFiles below makes the local variant read them
// from there instead of from the host. That is what makes -cache equivalent to
// the remote path rather than a lookalike.
//
// The suffixes cannot be hard-coded: dyld.go reads them from the cache header
// (bytes 24..56 of each subcache entry), so the set is only knowable by walking
// the cache the way openDyldCache does. Calling newStoreCache with a dumping
// opener does exactly that, and copies out every member it asks for.

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// featureFlagDomains are the only ones profilegen asks for
// (profilegen/features.go). Anything else in that directory is not read.
var featureFlagDomains = []string{"AppleMediaServices", "CFNetwork", "Foundation"}

// WriteCache extracts the pinned arm64e shared cache and the feature-flag
// plists under prefix and systemDir respectively.
//
// prefix is a path prefix, not a directory: members land at prefix+suffix, which
// is the layout OpenLocalStoreCache expects. systemDir receives one file per
// domain, named <domain>.plist.
func WriteCache(ctx context.Context, prefix, systemDir string) error {
	if ctx == nil {
		return fmt.Errorf("write cache: context is nil")
	}

	if prefix == "" {
		return fmt.Errorf("write cache: prefix is empty")
	}

	if systemDir == "" {
		return fmt.Errorf("write cache: system directory is empty")
	}

	client := &http.Client{}

	remote, err := openRemoteFile(ctx, client)
	if err != nil {
		return fmt.Errorf("write cache: open restore image: %w", err)
	}

	archive, err := zip.NewReader(remote, remote.size)
	if err != nil {
		return fmt.Errorf("write cache: read restore archive: %w", err)
	}

	if err := writeSharedCacheMembers(ctx, client, remote, archive, prefix); err != nil {
		return err
	}

	return writeFeatureFlags(ctx, client, remote, archive, systemDir)
}

func writeSharedCacheMembers(ctx context.Context, client *http.Client, remote io.ReaderAt, archive *zip.Reader, prefix string) error {
	entry, err := pinnedZipEntry(archive, systemOSImageName, systemOSArchiveSize, systemOSArchiveSize)
	if err != nil {
		return err
	}

	offset, err := entry.DataOffset()
	if err != nil {
		return fmt.Errorf("write shared cache: locate cryptex: %w", err)
	}

	image, err := newAEAReader(ctx, client,
		io.NewSectionReader(remote, offset, int64(entry.CompressedSize64)),
		int64(entry.CompressedSize64))
	if err != nil {
		return fmt.Errorf("write shared cache: open cryptex: %w", err)
	}

	if image.size != systemOSImageSize {
		return fmt.Errorf("write shared cache: cryptex does not match the pinned image")
	}

	extractor, closeExtractor, err := newAPFSExtractor(image, image.size)
	if err != nil {
		return err
	}

	defer func() { _ = closeExtractor() }()

	var written int

	opener := func(suffix string) (*dyldCacheFile, error) {
		member, err := extractor.openFile(ctx, arm64CachePath+suffix)
		if err != nil {
			return nil, err
		}

		destination := prefix + suffix

		out, err := os.Create(destination)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", destination, err)
		}

		if _, err := io.Copy(out, io.NewSectionReader(member, 0, member.size)); err != nil {
			_ = out.Close()

			return nil, fmt.Errorf("write %s: %w", destination, err)
		}

		if err := out.Close(); err != nil {
			return nil, fmt.Errorf("close %s: %w", destination, err)
		}

		written++

		file, err := os.Open(destination)
		if err != nil {
			return nil, fmt.Errorf("reopen %s: %w", destination, err)
		}

		info, err := file.Stat()
		if err != nil {
			_ = file.Close()

			return nil, fmt.Errorf("inspect %s: %w", destination, err)
		}

		return &dyldCacheFile{reader: file, size: info.Size(), close: file.Close}, nil
	}

	cache, err := newStoreCache(ctx, opener, func() error { return nil })
	if err != nil {
		return fmt.Errorf("write shared cache: %w", err)
	}

	if err := cache.Close(); err != nil {
		return fmt.Errorf("write shared cache: close: %w", err)
	}

	if written == 0 {
		return fmt.Errorf("write shared cache: the cache header listed no members")
	}

	fmt.Fprintf(os.Stderr, "dumped %d shared-cache member(s) under prefix %s\n", written, prefix)

	return nil
}

func writeFeatureFlags(ctx context.Context, client *http.Client, remote io.ReaderAt, archive *zip.Reader, directory string) error {
	entry, err := pinnedZipEntry(archive, fileSystemImageName, fileSystemArchiveSize, fileSystemArchiveSize)
	if err != nil {
		return err
	}

	offset, err := entry.DataOffset()
	if err != nil {
		return fmt.Errorf("write feature flags: locate filesystem: %w", err)
	}

	image, err := newAEAReader(ctx, client,
		io.NewSectionReader(remote, offset, int64(entry.CompressedSize64)),
		int64(entry.CompressedSize64))
	if err != nil {
		return fmt.Errorf("write feature flags: open filesystem: %w", err)
	}

	if image.size != fileSystemImageSize {
		return fmt.Errorf("write feature flags: filesystem does not match the pinned image")
	}

	extractor, closeExtractor, err := newAPFSExtractor(image, image.size)
	if err != nil {
		return err
	}

	defer func() { _ = closeExtractor() }()

	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("write feature flags: create %s: %w", directory, err)
	}

	for _, domain := range featureFlagDomains {
		source := "/System/Library/FeatureFlags/Domain/" + domain + ".plist"

		file, err := extractor.openFile(ctx, source)
		if err != nil {
			return fmt.Errorf("write feature flags: open %s: %w", source, err)
		}

		data, err := io.ReadAll(io.NewSectionReader(file, 0, file.size))
		if err != nil {
			return fmt.Errorf("write feature flags: read %s: %w", source, err)
		}

		destination := filepath.Join(directory, domain+".plist")
		if err := os.WriteFile(destination, data, 0o644); err != nil {
			return fmt.Errorf("write feature flags: write %s: %w", destination, err)
		}

		fmt.Fprintf(os.Stderr, "dumped %s (%d bytes)\n", destination, len(data))
	}

	return nil
}

// OpenLocalStoreCacheWithSystemFiles is OpenLocalStoreCache, except readSystemFile
// resolves inside systemDir instead of the host filesystem.
//
// This is the difference between a profile generated from the pinned image and
// one generated from whatever OS the runner happens to have.
func OpenLocalStoreCacheWithSystemFiles(ctx context.Context, prefix, systemDir string) (*StoreCache, error) {
	cache, err := OpenLocalStoreCache(ctx, prefix)
	if err != nil {
		return nil, err
	}

	cache.readSystemFile = func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(systemDir, filepath.Base(path)))
	}

	return cache, nil
}
