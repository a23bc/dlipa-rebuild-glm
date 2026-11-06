// Exports the four pinned macOS 27 SAP binaries.
//
// Upstream ipatool already knows how to pull them: assets.Load reads its cache
// and, when the cache is empty, resolves them from the pinned restore image
// (assets.go: macOSRestoreURL = UniversalMac_27.0.1_26A434_Restore.ipsw) and
// writes them back into the cache. Re-implementing the AEA/APFS/dyld-cache
// extraction here would be a second, worse copy of code that already exists.
//
// So this program does three things: call Load, then copy the four files out of
// the cache directory Load just populated, then let the workflow verify their
// digests.
//
// It has to live inside the ipatool module to reach internal/sap/assets, which
// is why the workflow copies it into that checkout before running it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// Kept in sync with assets.go: assetCacheDirectory. Not exported there.
const cacheDirectoryName = "apple-assets-macos-27-26A434-arm64-v1"

var requiredFiles = []string{"AppleMediaServices", "commerce", "CoreFP", "CoreFP.icxs"}

func main() {
	out := flag.String("out", "VendorAssets", "directory to write the binaries into")
	timeout := flag.Duration("timeout", 90*time.Minute, "upper bound for download and extraction")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Report before any os.Exit: the byte count matters most on the runs that
	// fail, and a deferred call would be skipped.
	egress := measureEgress()
	heap := startHeapSampler()
	err := run(ctx, *out)
	memory := heap.finish()
	egress.report()
	fmt.Printf("  heap: peak %s, cumulative allocated %s\n",
		formatBytes(int64(memory.peak)), formatBytes(int64(memory.totalAlloc)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// heapSampler watches the heap while the extraction runs, and reports two
// numbers: the highest live heap it saw, and the cumulative bytes the runtime
// ever allocated. go-macho pre-allocates the whole address span of the cached
// image before writing any of it, and that reservation is what a phone cannot
// satisfy -- but a large allocation that lives only while a 14.8 MB file is
// being written can fall between two samples. TotalAlloc cannot miss it, so the
// pair answers the question instead of guessing from whichever one you happened
// to look at.
type heapSampler struct {
	halt chan struct{}
	done chan heapSample
	peak atomic.Uint64
}

type heapSample struct {
	peak       uint64
	totalAlloc uint64
}

func startHeapSampler() *heapSampler {
	sampler := &heapSampler{halt: make(chan struct{}), done: make(chan heapSample, 1)}
	go func() {
		var stats runtime.MemStats
		// ReadMemStats stops the world, so this stays coarse on purpose.
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runtime.ReadMemStats(&stats)
				sampler.record(stats.HeapAlloc)
			case <-sampler.halt:
				runtime.ReadMemStats(&stats)
				sampler.record(stats.HeapAlloc)
				sampler.done <- heapSample{peak: sampler.peak.Load(), totalAlloc: stats.TotalAlloc}
				return
			}
		}
	}()
	return sampler
}

func (s *heapSampler) record(alloc uint64) {
	for {
		seen := s.peak.Load()
		if alloc <= seen || s.peak.CompareAndSwap(seen, alloc) {
			return
		}
	}
}

func (s *heapSampler) finish() heapSample {
	close(s.halt)
	return <-s.done
}

func run(ctx context.Context, out string) error {
	fmt.Println("==> resolving macOS 27 assets from the pinned restore image")
	if _, err := assets.Load(ctx); err != nil {
		return fmt.Errorf("load assets: %w", err)
	}

	root, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("user cache dir: %w", err)
	}
	source := filepath.Join(root, "ipatool", "sap", cacheDirectoryName)

	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create output: %w", err)
	}

	for _, name := range requiredFiles {
		from := filepath.Join(source, name)
		to := filepath.Join(out, name)
		if err := copyFile(from, to); err != nil {
			return fmt.Errorf("copy %s: %w", name, err)
		}
		fmt.Printf("  ok %s\n", name)
	}

	return nil
}

// egressCounter reports what the extraction actually pulls from Apple. The
// callers inside ipatool build bare clients (&http.Client{}), so they resolve to
// http.DefaultTransport, which is what lets this wrap them here instead of
// patching the library. Only bytes read out of a response body are counted: an
// unread range costs no traffic, so counting Content-Length would overstate it.
type egressCounter struct {
	base     http.RoundTripper
	started  time.Time
	requests atomic.Int64
	bytes    atomic.Int64
	largest  atomic.Int64
}

func measureEgress() *egressCounter {
	counter := &egressCounter{base: http.DefaultTransport, started: time.Now()}
	http.DefaultTransport = counter
	return counter
}

func (c *egressCounter) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := c.base.RoundTrip(request)
	if err != nil || response == nil {
		return response, err
	}
	c.requests.Add(1)
	response.Body = &countedBody{ReadCloser: response.Body, counter: c}
	return response, nil
}

func (c *egressCounter) report() {
	elapsed := time.Since(c.started)
	requests := c.requests.Load()
	total := c.bytes.Load()
	if requests == 0 {
		fmt.Println("  egress: no requests made (cache was already warm)")
		return
	}
	fmt.Printf("  egress: %s in %d requests, mean %s, largest %s\n",
		formatBytes(total), requests, formatBytes(total/requests), formatBytes(c.largest.Load()))
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		fmt.Printf("  elapsed: %s\n", elapsed.Round(time.Millisecond))
		return
	}
	fmt.Printf("  elapsed: %s (%s/s)\n", elapsed.Round(time.Millisecond),
		formatBytes(int64(float64(total)/seconds)))
}

type countedBody struct {
	io.ReadCloser
	counter *egressCounter
	read    int64
}

func (b *countedBody) Read(data []byte) (int, error) {
	count, err := b.ReadCloser.Read(data)
	if count > 0 {
		b.read += int64(count)
		b.counter.bytes.Add(int64(count))
	}
	return count, err
}

func (b *countedBody) Close() error {
	for {
		seen := b.counter.largest.Load()
		if b.read <= seen || b.counter.largest.CompareAndSwap(seen, b.read) {
			break
		}
	}
	return b.ReadCloser.Close()
}

func formatBytes(count int64) string {
	const unit = 1024
	if count < unit {
		return fmt.Sprintf("%d B", count)
	}
	div, exp := int64(unit), 0
	for value := count / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(count)/float64(div), "KMGTPE"[exp])
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(to)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
