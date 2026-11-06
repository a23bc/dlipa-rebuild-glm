// Package measure reports what a long-running extraction costs on the device,
// rather than only whether it survived. The same figures come out of the CI
// exporter, so a phone number can be compared against a runner number instead
// of being argued about.
package measure

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Session watches one extraction: bytes actually transferred, and the Go heap
// while it ran. Call Finish exactly once; it restores the transport it replaced.
type Session struct {
	previous  http.RoundTripper
	halt      chan struct{}
	done      chan heapSample
	requests  atomic.Uint64
	bytes     atomic.Uint64
	largest   atomic.Uint64
	peak      atomic.Uint64
	startedAt time.Time
}

type heapSample struct {
	peak       uint64
	totalAlloc uint64
}

// Start replaces http.DefaultTransport. The clients inside the extractor are
// bare (&http.Client{}), so they resolve to it, and this way the counting does
// not reach into the extractor's own code.
func Start() *Session {
	session := &Session{
		previous:  http.DefaultTransport,
		halt:      make(chan struct{}),
		done:      make(chan heapSample, 1),
		startedAt: time.Now(),
	}
	http.DefaultTransport = session
	go session.sampleHeap()
	return session
}

// RoundTrip counts the bytes read out of each response body, not Content-Length:
// a range that is opened and abandoned transfers nothing, and counting the
// header would overstate the traffic a phone plan has to carry.
func (s *Session) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := s.previous.RoundTrip(request)
	if err != nil || response == nil {
		return response, err
	}
	s.requests.Add(1)
	response.Body = &countedBody{ReadCloser: response.Body, session: s}
	return response, nil
}

func (s *Session) sampleHeap() {
	var stats runtime.MemStats
	// ReadMemStats stops the world, so this stays coarse on purpose.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			runtime.ReadMemStats(&stats)
			s.recordHeap(stats.HeapAlloc)
		case <-s.halt:
			runtime.ReadMemStats(&stats)
			s.recordHeap(stats.HeapAlloc)
			s.done <- heapSample{peak: s.peak.Load(), totalAlloc: stats.TotalAlloc}
			return
		}
	}
}

func (s *Session) recordHeap(alloc uint64) {
	for {
		seen := s.peak.Load()
		if alloc <= seen || s.peak.CompareAndSwap(seen, alloc) {
			return
		}
	}
}

// Finish returns the summary. It is one line because the caller writes it into a
// log view that already truncates.
func (s *Session) Finish() string {
	close(s.halt)
	http.DefaultTransport = s.previous
	heap := <-s.done
	elapsed := time.Since(s.startedAt).Round(time.Second)
	requests := s.requests.Load()
	transfer := s.bytes.Load()

	if requests == 0 {
		return fmt.Sprintf("no requests (cache warm?), peak heap %s in %s",
			Bytes(heap.peak), elapsed)
	}
	// Cumulative allocation rides alongside the peak because a reservation that
	// lives only while a file is flushed can fall between two samples; the
	// cumulative figure cannot miss it.
	return fmt.Sprintf(
		"%s in %d requests (mean %s, largest %s), peak heap %s, allocated %s, %s",
		Bytes(transfer), requests, Bytes(transfer/requests), Bytes(s.largest.Load()),
		Bytes(heap.peak), Bytes(heap.totalAlloc), elapsed)
}

type countedBody struct {
	io.ReadCloser
	session *Session
	read    uint64
}

func (b *countedBody) Read(data []byte) (int, error) {
	count, err := b.ReadCloser.Read(data)
	if count > 0 {
		b.read += uint64(count)
		b.session.bytes.Add(uint64(count))
	}
	return count, err
}

func (b *countedBody) Close() error {
	for {
		seen := b.session.largest.Load()
		if b.read <= seen || b.session.largest.CompareAndSwap(seen, b.read) {
			break
		}
	}
	return b.ReadCloser.Close()
}

// Bytes formats a count the way the CI exporter does, so the two logs read alike.
func Bytes(count uint64) string {
	const unit = 1024
	if count < unit {
		return fmt.Sprintf("%d B", count)
	}
	div, exp := uint64(unit), 0
	for value := count / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(count)/float64(div), "KMGTPE"[exp])
}
