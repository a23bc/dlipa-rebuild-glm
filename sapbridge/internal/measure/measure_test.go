package measure

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// These tests exist because the numbers they check are the ones read off a phone
// to decide whether in-app asset extraction fits at all. A wrong transfer count
// or a lost peak would send that decision the wrong way with no other symptom.

type stubTransport struct{ size int }

func (s stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusPartialContent,
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", s.size))),
	}, nil
}

// counting puts the stub underneath the session rather than over it: Start
// captures whatever DefaultTransport holds at the time it is called, so a stub
// installed afterwards would be bypassed and the count would read zero.
func counting(t *testing.T, size int) *Session {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = stubTransport{size: size}
	t.Cleanup(func() { http.DefaultTransport = previous })
	return Start()
}

func mustGet(t *testing.T) *http.Request {
	t.Helper()
	// http.NewRequest, not httptest.NewRequest: the latter sets RequestURI, which
	// a client request is not allowed to carry.
	request, err := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return request
}

func fetch(t *testing.T, read int64) {
	t.Helper()
	response, err := (&http.Client{}).Do(
		mustGet(t))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if read > 0 {
		if _, err := io.CopyN(io.Discard, response.Body, read); err != nil {
			t.Fatalf("read body: %v", err)
		}
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestSummaryCountsTheBodyItReads pins the plain case.
func TestSummaryCountsTheBodyItReads(t *testing.T) {
	session := counting(t, 512)
	fetch(t, 512)

	if summary := session.Finish(); !strings.HasPrefix(
		summary, "512 B in 1 requests (mean 512 B, largest 512 B)") {
		t.Errorf("summary = %q, want the 512 B count first", summary)
	}
}

// TestPartialReadCountsOnlyWhatArrived is the whole point of counting reads: a
// 4 KiB range of which 1 KiB is consumed must report 1 KiB, not 4 KiB.
func TestPartialReadCountsOnlyWhatArrived(t *testing.T) {
	session := counting(t, 4096)
	fetch(t, 1024)

	if summary := session.Finish(); !strings.HasPrefix(summary, "1.0 KiB in 1 requests") {
		t.Errorf("summary = %q, want 1.0 KiB", summary)
	}
}

// TestUnreadBodyIsNotCounted covers a range that was opened and abandoned.
func TestUnreadBodyIsNotCounted(t *testing.T) {
	session := counting(t, 4096)
	fetch(t, 0)

	if summary := session.Finish(); !strings.HasPrefix(summary, "0 B in 1 requests") {
		t.Errorf("summary = %q, want a zero transfer", summary)
	}
}

// TestFinishRestoresTheTransport matters because Start rewrites a process-wide
// default: leaving it installed would count every later request in the app, and
// a second fetch would report the first one's traffic as its own.
func TestFinishRestoresTheTransport(t *testing.T) {
	previous := http.DefaultTransport
	session := Start()
	if http.DefaultTransport == previous {
		t.Fatal("Start did not install itself")
	}
	session.Finish()

	if http.DefaultTransport != previous {
		t.Error("Finish left the replacement transport installed")
	}
}

func TestWarmCacheSaysSo(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })

	if summary := Start().Finish(); !strings.Contains(summary, "no requests") {
		t.Errorf("summary = %q, want the warm-cache wording", summary)
	}
}
