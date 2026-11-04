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

	// FairPlay data goes in the same pass: it is another entry, not a modification.
	sinfs, sinfErr := sinfEntries(source)
	if sinfErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] patch ipa: sinfs not injected: %v\n", sinfErr)
	}

	all := append([]extraEntry{{Name: "iTunesMetadata.plist", Data: entries}}, sinfs...)

	if err := appendToZip(path, tmpPath, all); err != nil {
		_ = os.Remove(tmpPath)

		return "", err
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		return "", fmt.Errorf("patch ipa: rename: %w", err)
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

// sinfEntries builds the SC_Info entries the package is missing.
//
// The destination paths come from SC_Info/Manifest.plist's SinfPaths, paired with
// the sinfs by index -- that is the upstream tool's contract, and the order is what
// matters, not the id field.
func sinfEntries(source *zip.ReadCloser) ([]extraEntry, error) {
	records := loadSinfs()
	if len(records) == 0 {
		return nil, fmt.Errorf("no sinfs were recorded for this download")
	}

	appDir := mainAppDirectory(source)
	if appDir == "" {
		return nil, fmt.Errorf("no Payload/*.app in the package")
	}

	paths, err := sinfPaths(source, appDir)
	if err != nil {
		return nil, err
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("no SinfPaths and no CFBundleExecutable to derive them from")
	}

	if len(records) < len(paths) {
		paths = paths[:len(records)]
	}

	entries := make([]extraEntry, 0, len(paths))

	for index, relative := range paths {
		entries = append(entries, extraEntry{
			Name: appDir + relative,
			Data: records[index].Sinf,
		})
	}

	return entries, nil
}

func mainAppDirectory(source *zip.ReadCloser) string {
	for _, file := range source.File {
		trimmed := strings.TrimPrefix(file.Name, "Payload/")
		if trimmed == file.Name {
			continue
		}

		// "Name.app/" carries the slash that makes it a directory entry, so counting
		// slashes is the check -- looking for the absence of one never matches.
		if strings.HasSuffix(trimmed, ".app/") && strings.Count(trimmed, "/") == 1 {
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
