package assets

// Dumps the pinned dyld shared cache to disk so profilegen can run offline.
//
// profilegen takes -cache <prefix> and OpenLocalStoreCache opens <prefix>+suffix,
// so it needs the members as real files. Nothing writes them today:
// OpenRemoteStoreCache streams them out of the restore image through an AEA
// reader and an APFS extractor and closes over that stream when it is done.
//
// The suffixes cannot be hard-coded. They are read from the cache header itself
// (dyld.go reads bytes 24..56 of each subcache entry), so the only way to learn
// the set is to walk the cache the way openDyldCache does -- which is what
// calling newStoreCache with a dumping opener does. Every member the cache asks
// for is copied out on the way past.
//
// This lives in package assets because everything it needs -- openRemoteFile,
// pinnedZipEntry, newAEAReader, newAPFSExtractor, newStoreCache -- is unexported.

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

// WriteSharedCache extracts the pinned arm64e shared cache under prefix.
//
// prefix is a path prefix, not a directory: members land at prefix+suffix, so
// passing dir+"/dyld_shared_cache_arm64e" produces the layout
// OpenLocalStoreCache expects.
func WriteSharedCache(ctx context.Context, prefix string) error {
	if ctx == nil {
		return fmt.Errorf("write shared cache: context is nil")
	}

	if prefix == "" {
		return fmt.Errorf("write shared cache: prefix is empty")
	}

	client := &http.Client{}

	remote, err := openRemoteFile(ctx, client)
	if err != nil {
		return fmt.Errorf("write shared cache: open restore image: %w", err)
	}

	archive, err := zip.NewReader(remote, remote.size)
	if err != nil {
		return fmt.Errorf("write shared cache: read restore archive: %w", err)
	}

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

		fmt.Fprintf(os.Stderr, "dumped %s (%d bytes)\n", destination, member.size)

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

	// newStoreCache walks every subcache in the header, so every member is
	// requested and therefore dumped. Its result is not needed.
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

	fmt.Fprintf(os.Stderr, "dumped %d member(s) under prefix %s\n", written, prefix)

	return nil
}
