package assetsremote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	remoteReadAttempts    = 3
	restoreImageUserAgent = "Mozilla/5.0"
	// The callers of ReaderAt walk the restore image in small pieces: APFS uses
	// 4 KiB blocks. One HTTP range request per piece made a fresh install take
	// about six minutes (610-2). Fetch a modest block per request and serve the
	// small reads out of it. 256 KiB cuts request count 64x without over-fetching
	// whole megabytes for the sparse reads the APFS and dyld extractors make;
	// an 8 MiB block (run 611) fetched far more than it saved.
	remoteReadAhead = 256 << 10
)

type remoteFile struct {
	ctx    context.Context
	client *http.Client
	url    string
	size   int64

	mu            sync.Mutex
	cache         []byte
	cacheStart    int64
	blocksFetched int
	bytesFetched  int64
}

// Stats reports how much of the restore image was actually fetched. The
// extractors read sparse extents; this line is the only way to tell a slow
// network from a block size that fetches too much.
func (r *remoteFile) Stats() (int, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.blocksFetched, r.bytesFetched
}

//nolint:wsl // Request construction and validation are clearer in protocol order.
func openRemoteFile(ctx context.Context, client *http.Client) (*remoteFile, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, macOSRestoreURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create remote image request: %w", err)
	}

	request.Header.Set("User-Agent", restoreImageUserAgent)
	request.Header.Set("Range", "bytes=0-0")
	response, err := client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("open remote image: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("open remote image: server returned %s without byte-range support", response.Status)
	}

	start, end, size, err := parseContentRange(response.Header.Get("Content-Range"))
	if err != nil {
		return nil, fmt.Errorf("open remote image: %w", err)
	}
	if start != 0 || end != 0 {
		return nil, fmt.Errorf("open remote image: server returned unexpected byte range %d-%d", start, end)
	}

	return &remoteFile{ctx: ctx, client: client, url: macOSRestoreURL, size: size}, nil
}

//nolint:wsl // Parsing checks are clearer in wire-format order.
func parseContentRange(value string) (int64, int64, int64, error) {
	unitAndRange, total, ok := strings.Cut(value, "/")
	if !ok || total == "" || total == "*" {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	size, err := strconv.ParseInt(total, 10, 64)
	if err != nil || size <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	rangeValue, ok := strings.CutPrefix(unitAndRange, "bytes ")
	if !ok {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}

	startValue, endValue, ok := strings.Cut(rangeValue, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}
	start, startErr := strconv.ParseInt(startValue, 10, 64)
	end, endErr := strconv.ParseInt(endValue, 10, 64)
	if startErr != nil || endErr != nil || start < 0 || end < start || end >= size {
		return 0, 0, 0, fmt.Errorf("invalid Content-Range %q", value)
	}

	return start, end, size, nil
}

// readBlock fetches one aligned block. It keeps the three attempts and the
// strict Content-Range check of the original per-read request.
//
//nolint:wsl // Range request validation is clearer in protocol order.
func (r *remoteFile) readBlock(start int64, length int) ([]byte, error) {
	end := start + int64(length) - 1
	if end >= r.size {
		end = r.size - 1
	}

	var lastErr error

	for attempt := 0; attempt < remoteReadAttempts; attempt++ {
		request, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
		if err != nil {
			return nil, fmt.Errorf("create remote range request: %w", err)
		}

		request.Header.Set("User-Agent", restoreImageUserAgent)
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
		response, err := r.client.Do(request)
		if err != nil {
			lastErr = err

			continue
		}

		if response.StatusCode != http.StatusPartialContent {
			response.Body.Close()

			return nil, fmt.Errorf("read remote image range: server returned %s", response.Status)
		}
		actualStart, actualEnd, actualSize, err := parseContentRange(response.Header.Get("Content-Range"))

		if err != nil || actualStart != start || actualEnd != end || actualSize != r.size {
			response.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("read remote image range: %w", err)
			}

			return nil, fmt.Errorf("read remote image range: server returned bytes %d-%d/%d, expected %d-%d/%d", actualStart, actualEnd, actualSize, start, end, r.size)
		}

		block := make([]byte, int(end-start+1))
		_, readErr := io.ReadFull(response.Body, block)
		closeErr := response.Body.Close()
		if readErr == nil && closeErr != nil {
			readErr = closeErr
		}

		if readErr == nil {
			r.blocksFetched++
			r.bytesFetched += int64(len(block))

			return block, nil
		}

		lastErr = readErr
	}

	return nil, fmt.Errorf("read remote block at %d: %w", start, lastErr)
}

func (r *remoteFile) ReadAt(data []byte, offset int64) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	if offset < 0 {
		return 0, errors.New("negative remote image offset")
	}

	if offset >= r.size {
		return 0, io.EOF
	}

	wanted := len(data)
	if remaining := r.size - offset; int64(wanted) > remaining {
		wanted = int(remaining)
	}

	// The cache belongs to this file; guard it so concurrent ReaderAt callers
	// cannot see a half-filled block.
	r.mu.Lock()
	defer r.mu.Unlock()

	total := 0

	for total < wanted {
		position := offset + int64(total)
		inBlock := position - r.cacheStart

		if r.cache == nil || inBlock < 0 || inBlock >= int64(len(r.cache)) {
			start := (position / remoteReadAhead) * remoteReadAhead
			block, err := r.readBlock(start, remoteReadAhead)
			if err != nil {
				return total, fmt.Errorf("read remote image at offset %d: %w", position, err)
			}

			r.cache, r.cacheStart = block, start
			inBlock = position - r.cacheStart
		}

		count := copy(data[total:wanted], r.cache[inBlock:])
		if count == 0 {
			return total, io.ErrUnexpectedEOF
		}

		total += count
	}

	if wanted != len(data) {
		return total, io.EOF
	}

	return total, nil
}
