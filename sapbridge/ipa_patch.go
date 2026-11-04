package sapbridge

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// PatchIPA rewrites the account fields inside an .ipa and writes a sibling file.
//
// Step 2 of 4.6: the package carries an iTunesMetadata.plist with the account
// that bought it. Apple's installer and the store both read `apple-id` and
// `userName` from it, so a package downloaded for one account is labelled with
// that account. Rewriting them is the whole of this step; step 3 (the FairPlay
// sinfs under SC_Info) is separate because it needs the manifest read out of the
// package first.
//
// The original file is left alone: the patched copy is written beside it, so a
// bad patch is a deleted file rather than a lost download.
func PatchIPA(path, email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("patch ipa: no account email to write")
	}

	source, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("patch ipa: open: %w", err)
	}

	defer source.Close()

	metadata := findMetadata(source)
	if metadata == nil {
		return "", fmt.Errorf("patch ipa: no iTunesMetadata.plist in the package")
	}

	entries, err := patchMetadata(metadata, email)
	if err != nil {
		return "", err
	}

	outPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".patched.ipa"
	tmpPath := outPath + ".tmp"

	if err := writePatched(source, entries, outPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)

		return "", err
	}

	return outPath, nil
}

// findMetadata locates the plist at the package root.
func findMetadata(source *zip.ReadCloser) *zip.File {
	for _, file := range source.File {
		if file.Name == "iTunesMetadata.plist" {
			return file
		}
	}

	return nil
}

// patchMetadata decodes the plist, sets the two account fields and re-encodes it.
//
// Binary rather than XML: the original ships as binary, and the installer is not
// the place to discover that a format change matters.
func patchMetadata(file *zip.File, email string) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("patch ipa: open metadata: %w", err)
	}

	defer reader.Close()

	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("patch ipa: read metadata: %w", err)
	}

	var document map[string]any
	if _, err := plist.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("patch ipa: decode metadata: %w", err)
	}

	document["apple-id"] = email
	document["userName"] = email

	encoded, err := plist.Marshal(document, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("patch ipa: encode metadata: %w", err)
	}

	return encoded, nil
}

// writePatched copies every entry, substituting the rewritten metadata.
//
// Writer.Copy moves the entries' compressed bytes across untouched: no
// recompression, no recomputed checksums. Only the metadata entry is rebuilt,
// because its contents changed. Whether the reconstructed headers are faithful
// enough for the installer is the open question this design is meant to answer
// cheaply -- see the note in the plan about falling back to raw local headers.
func writePatched(source *zip.ReadCloser, metadata []byte, outPath, tmpPath string) error {
	target, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("patch ipa: create: %w", err)
	}

	writer := zip.NewWriter(target)

	for _, file := range source.File {
		if file.Name == "iTunesMetadata.plist" {
			header := file.FileHeader
			//
			// Sizes and CRC no longer match the rewritten body; zero them so the
			// writer computes them rather than trusting stale values.
			header.CRC32 = 0
			header.CompressedSize = 0
			header.CompressedSize64 = 0
			header.UncompressedSize = 0
			header.UncompressedSize64 = 0

			entry, err := writer.CreateHeader(&header)
			if err != nil {
				_ = target.Close()

				return fmt.Errorf("patch ipa: create metadata entry: %w", err)
			}

			if _, err := entry.Write(metadata); err != nil {
				_ = target.Close()

				return fmt.Errorf("patch ipa: write metadata: %w", err)
			}

			continue
		}

		if err := writer.Copy(file); err != nil {
			_ = target.Close()

			return fmt.Errorf("patch ipa: copy %s: %w", file.Name, err)
		}
	}

	if err := writer.Close(); err != nil {
		_ = target.Close()

		return fmt.Errorf("patch ipa: finish: %w", err)
	}

	if err := target.Close(); err != nil {
		return fmt.Errorf("patch ipa: close: %w", err)
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("patch ipa: rename: %w", err)
	}

	return nil
}
