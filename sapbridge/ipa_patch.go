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

	// Apple's package carries no iTunesMetadata.plist: the store adds it from the
	// download response when it installs. So it is created here from the dictionary
	// the response supplied, and an existing one is treated the same way -- read,
	// relabelled, written back.
	raw, err := metadataDocument(source)
	if err != nil {
		return "", err
	}

	entries, err := patchMetadata(raw, email)
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

// metadataDocument returns the plist's bytes: the one inside the package if there
// is one, otherwise the dictionary kept from the download response.
func metadataDocument(source *zip.ReadCloser) ([]byte, error) {
	for _, file := range source.File {
		if file.Name != "iTunesMetadata.plist" {
			continue
		}

		reader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("patch ipa: open metadata: %w", err)
		}

		defer reader.Close()

		return io.ReadAll(reader)
	}

	raw, err := os.ReadFile(metadataSlot())
	if err != nil {
		return nil, fmt.Errorf("patch ipa: the package has no iTunesMetadata.plist and none was recorded: %w", err)
	}

	return raw, nil
}

// metadataSlot is the file the bridge writes the response's metadata dictionary to
// after a successful download. Kept in step with metadataSlotPath in internal/sap.
func metadataSlot() string {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}

	return filepath.Join(root, "dlipa", "last-metadata.plist")
}

// patchMetadata decodes the plist, sets the two account fields and re-encodes it.
//
// Binary rather than XML: the original ships as binary, and the installer is not
// the place to discover that a format change matters.
func patchMetadata(raw []byte, email string) ([]byte, error) {
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
	replaced := false

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

			replaced = true

			continue
		}

		if err := writer.Copy(file); err != nil {
			_ = target.Close()

			return fmt.Errorf("patch ipa: copy %s: %w", file.Name, err)
		}
	}

	// Most packages have no metadata entry at all, which is why this adds one
	// rather than only replacing it: the store adds the file at install time, so a
	// package meant to be installed by something else needs it present.
	if !replaced {
		entry, err := writer.Create("iTunesMetadata.plist")
		if err != nil {
			_ = target.Close()

			return fmt.Errorf("patch ipa: add metadata entry: %w", err)
		}

		if _, err := entry.Write(metadata); err != nil {
			_ = target.Close()

			return fmt.Errorf("patch ipa: write metadata: %w", err)
		}
	}

	// FairPlay authorisation data goes in last: the package installs without it, but
	// the app cannot be decrypted at launch, which is what "install succeeded and
	// then nothing opens" looks like.
	if err := injectSinfs(source, writer); err != nil {
		fmt.Fprintf(os.Stderr, "[SAP] patch ipa: sinfs not injected: %v\n", err)
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

// sinfRecord mirrors the response entry.
type sinfRecord struct {
	ID   int64  `plist:"id,omitempty"`
	Sinf []byte `plist:"sinf,omitempty"`
}

// loadSinfs reads the array the bridge saved after the download.
func loadSinfs() []sinfRecord {
	root, err := os.UserCacheDir()
	if err != nil {
		root = os.TempDir()
	}

	raw, err := os.ReadFile(filepath.Join(root, "dlipa", "last-sinfs.plist"))
	if err != nil || len(raw) == 0 {
		return nil
	}

	var records []sinfRecord
	if _, err := plist.Unmarshal(raw, &records); err != nil {
		return nil
	}

	return records
}

// injectSinfs writes the FairPlay data into the main app's SC_Info directory.
//
// The destination paths come from SC_Info/Manifest.plist's SinfPaths, paired with
// the sinfs by index -- that is how the upstream tool does it, and the order is the
// contract, not the id field.
func injectSinfs(source *zip.ReadCloser, writer *zip.Writer) error {
	records := loadSinfs()
	if len(records) == 0 {
		return fmt.Errorf("no sinfs were recorded for this download")
	}

	appDir := mainAppDirectory(source)
	if appDir == "" {
		return fmt.Errorf("no Payload/*.app in the package")
	}

	paths, err := sinfPaths(source, appDir)
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		return fmt.Errorf("no SinfPaths and no CFBundleExecutable to derive them from")
	}

	if len(records) < len(paths) {
		// Fewer sinfs than destinations: write what matches rather than nothing.
		paths = paths[:len(records)]
	}

	for index, relative := range paths {
		entry, err := writer.Create(appDir + relative)
		if err != nil {
			return fmt.Errorf("create %s: %w", relative, err)
		}

		if _, err := entry.Write(records[index].Sinf); err != nil {
			return fmt.Errorf("write %s: %w", relative, err)
		}
	}

	return nil
}

// mainAppDirectory is "Payload/<name>.app/", the bundle the sinfs belong to.
func mainAppDirectory(source *zip.ReadCloser) string {
	for _, file := range source.File {
		trimmed := strings.TrimPrefix(file.Name, "Payload/")
		if trimmed == file.Name {
			continue
		}

		if strings.HasSuffix(trimmed, ".app/") && !strings.Contains(trimmed, "/") {
			return "Payload/" + trimmed
		}
	}

	return ""
}

// sinfPaths prefers SC_Info/Manifest.plist, falling back to the executable name.
func sinfPaths(source *zip.ReadCloser, appDir string) ([]string, error) {
	if manifest := readZipFile(source, appDir+"SC_Info/Manifest.plist"); manifest != nil {
		var document struct {
			SinfPaths []string `plist:"SinfPaths"`
		}

		if _, err := plist.Unmarshal(manifest, &document); err == nil && len(document.SinfPaths) > 0 {
			return document.SinfPaths, nil
		}
	}

	if info := readZipFile(source, appDir+"Info.plist"); info != nil {
		var document struct {
			Executable string `plist:"CFBundleExecutable"`
		}

		if _, err := plist.Unmarshal(info, &document); err == nil && document.Executable != "" {
			return []string{"SC_Info/" + document.Executable + ".sinf"}, nil
		}
	}

	return nil, nil
}

func readZipFile(source *zip.ReadCloser, name string) []byte {
	for _, file := range source.File {
		if file.Name != name {
			continue
		}

		reader, err := file.Open()
		if err != nil {
			return nil
		}

		defer reader.Close()

		data, err := io.ReadAll(reader)
		if err != nil {
			return nil
		}

		return data
	}

	return nil
}
