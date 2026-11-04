package sapbridge

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The property that matters is not "the output is a valid zip" but "the entries that
// were already there are byte-identical". Apple's packages carry an alignment record
// in each local header that the central directory does not describe, so a rebuild
// passes every structural check while quietly dropping the thing the installer
// cares about.

func TestAppendToZipKeepsExistingRecords(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.zip")

	original := writeTestZip(t, source, map[string]string{
		"Payload/Demo.app/Info.plist": "<plist/>",
		"Payload/Demo.app/Demo":       "binary-bytes",
	})

	target := filepath.Join(dir, "patched.zip")

	err := appendToZip(source, target, []extraEntry{
		{Name: "iTunesMetadata.plist", Data: []byte("<plist>metadata</plist>")},
		{Name: "Payload/Demo.app/SC_Info/Demo.sinf", Data: []byte("fairplay")},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	patched := readAll(t, target)

	// Every original entry must appear in the output exactly as it did.
	for name, local := range original {
		if !bytes.Contains(patched, local) {
			t.Fatalf("local record for %s was not preserved verbatim", name)
		}
	}

	reader, err := zip.OpenReader(target)
	if err != nil {
		t.Fatalf("output is not a readable zip: %v", err)
	}

	defer reader.Close()

	names := map[string]bool{}
	for _, file := range reader.File {
		names[file.Name] = true
	}

	for _, want := range []string{"iTunesMetadata.plist", "Payload/Demo.app/SC_Info/Demo.sinf"} {
		if !names[want] {
			t.Fatalf("missing %s in the output", want)
		}
	}

	if !names["Payload/Demo.app/Info.plist"] {
		t.Fatal("original entries disappeared")
	}
}

func TestAppendToZipSkipsExistingNames(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.zip")

	writeTestZip(t, source, map[string]string{"iTunesMetadata.plist": "original"})

	target := filepath.Join(dir, "patched.zip")

	if err := appendToZip(source, target, []extraEntry{
		{Name: "iTunesMetadata.plist", Data: []byte("replacement")},
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	reader, err := zip.OpenReader(target)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	defer reader.Close()

	count := 0
	for _, file := range reader.File {
		if file.Name == "iTunesMetadata.plist" {
			count++
		}
	}

	if count != 1 {
		t.Fatalf("expected the existing entry to be left alone, found %d copies", count)
	}
}

// writeTestZip builds a small archive and returns each entry's raw local record.
func writeTestZip(t *testing.T, path string, entries map[string]string) map[string][]byte {
	t.Helper()

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	writer := zip.NewWriter(file)

	for name, content := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create entry: %v", err)
		}

		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	defer reader.Close()

	raw := readAll(t, path)
	records := map[string][]byte{}

	for _, entry := range reader.File {
		data, err := entry.DataOffset()
		if err != nil {
			t.Fatalf("data offset: %v", err)
		}

		start := int(data) - 30 - len(entry.Name) - len(entry.Extra)
		end := int(data) + int(entry.CompressedSize64)

		records[entry.Name] = raw[start:end]
	}

	return records
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	return data
}
