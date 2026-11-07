package sapbridge

import (
	"archive/zip"
	"fmt"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/install"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
// The file is patched in place, through a temporary: a failure leaves the original
// untouched, and a success leaves exactly one package behind.
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

	// Patched in place: one file per download, no sibling to keep in step with.
	tmpPath := path + ".patching"

	// FairPlay data goes in the same pass: it is another entry, not a modification.
	sinfs, sinfErr := sinfEntries(source)
	if sinfErr != nil {
		fmt.Fprintf(os.Stderr, "[SAP] patch ipa: sinfs not injected: %v\n", sinfErr)
	}

	all := append([]extraEntry{{Name: "iTunesMetadata.plist", Data: entries}}, sinfs...)

	// How much of that list the package does not already hold. The reason this is
	// counted before writing is that appendToZip copies every payload byte
	// verbatim and then skips the names it finds: a package that already carries
	// everything therefore costs a full read plus a full write of its own size and
	// changes nothing on disk. That is the whole of "the bigger the package the
	// longer the injection, and the more injections the worse it gets" -- the cost
	// is linear in the package and blind to what is being added -- and when nothing
	// is new the rewrite is simply skipped, leaving the sidecar below to be written
	// as before. The line that prints when it does rewrite is the measurement that
	// says what a pass costs on this device, because none of that was recorded.
	pending := pendingEntries(source, all)

	if pending > 0 {
		size, sizeErr := fileSize(path)

		start := time.Now()

		if err := appendToZip(path, tmpPath, all); err != nil {
			_ = os.Remove(tmpPath)

			return "", err
		}

		if err := os.Rename(tmpPath, path); err != nil {
			return "", fmt.Errorf("patch ipa: rename: %w", err)
		}

		elapsed := time.Since(start)
		rate := 0.0

		if elapsed.Seconds() > 0 && sizeErr == nil {
			rate = float64(size) / (1 << 20) / elapsed.Seconds()
		}

		fmt.Fprintf(os.Stderr, "[SAP] patch ipa: rewrote %s: %d MiB, %d of %d entries new, %s, %.0f MiB/s\n",
			filepath.Base(path), size>>20, pending, len(all),
			elapsed.Round(time.Millisecond), rate)
	} else {
		fmt.Fprintf(os.Stderr, "[SAP] patch ipa: %s already carries all %d entries; nothing rewritten\n",
			filepath.Base(path), len(all))
	}

	// What the package says about itself, left beside it for the app to read. The
	// alternative is calling into the bridge or opening the zip again for every row.
	if identity, ok := install.IdentityFor(path); ok {
		sidecar := fmt.Sprintf(`{"bundleID":%q,"version":%q,"minimumOS":%q,"title":%q,"size":%d}`,
			identity.BundleID, identity.Version, identity.MinimumOS, identity.Title, identity.Size)

		if err := os.WriteFile(path+".identity.json", []byte(sidecar), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "[SAP] patch ipa: identity sidecar: %v\n", err)
		}
	}

	return path, nil
}

// pendingEntries counts what the package does not carry yet.
//
// The names decide, because appendToZip skips an entry whose name it finds and
// copies every payload byte regardless: so a package that already holds all of
// them is a pass that reads and writes its whole size and changes no byte.
// Counting first is the only way to know that before paying for it.
func pendingEntries(source *zip.ReadCloser, entries []extraEntry) int {
	present := make(map[string]struct{}, len(source.File))
	for _, file := range source.File {
		present[file.Name] = struct{}{}
	}

	var pending int

	for _, entry := range entries {
		if _, found := present[entry.Name]; !found {
			pending++
		}
	}

	return pending
}

// fileSize answers how much a patch pass has to copy.
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("patch ipa: stat: %w", err)
	}

	return info.Size(), nil
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
