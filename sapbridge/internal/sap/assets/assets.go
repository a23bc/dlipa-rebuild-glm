package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	macOSVersion        = "27.0.1"
	macOSBuild          = "26A434"
	macOSRestoreURL     = "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw"
	assetCacheDirectory = "apple-assets-macos-27-26A434-arm64-v1"
)

type Bundle struct {
	AppleMediaServices []byte
	Commerce           []byte
	CoreFP             []byte
	CoreFPICXS         []byte
}

type fileSpec struct {
	name   string
	size   int
	digest [32]byte
}

var requiredFiles = []fileSpec{
	{
		name:   "AppleMediaServices",
		size:   14813888,
		digest: mustDigest("95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4"),
	},
	{
		name:   "commerce",
		size:   8092640,
		digest: mustDigest("76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9"),
	},
	{
		name:   "CoreFP",
		size:   94842464,
		digest: mustDigest("2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46"),
	},
	{
		name:   "CoreFP.icxs",
		size:   7365344,
		digest: mustDigest("cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b"),
	},
}

// Load resolves and caches the pinned macOS framework profile used by SAP,
// kbsync generation, and package decryption.
func Load(ctx context.Context) (Bundle, error) {
	if ctx == nil {
		return Bundle{}, errors.New("apple asset context is nil")
	}

	if err := ctx.Err(); err != nil {
		return Bundle{}, fmt.Errorf("load Apple assets: %w", err)
	}

	directory, err := cacheDirectory()
	if err != nil {
		return Bundle{}, err
	}

	if bundle, err := readCache(directory); err == nil {
		return bundle, nil
	}

	// This build bundles the four Apple binaries rather than downloading them
	// from the macOS restore image, so there is no remote fallback. The app must
	// place the files in the cache directory, or set sapbridge.BundleDir.
	return Bundle{}, fmt.Errorf("Apple SAP assets are not present in %s; copy the four pinned binaries there or set sapbridge.BundleDir", directory)
}

func cacheDirectory() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache directory: %w", err)
	}

	return filepath.Join(root, "ipatool", "sap", assetCacheDirectory), nil
}

func readCache(directory string) (Bundle, error) {
	files := make(map[string][]byte, len(requiredFiles))

	for _, spec := range requiredFiles {
		data, err := readCacheFile(filepath.Join(directory, spec.name), spec)
		if err != nil {
			return Bundle{}, fmt.Errorf("read cached Apple SAP asset %s: %w", spec.name, err)
		}

		files[spec.name] = data
	}

	// validate() is deliberately not called here: it hashes each entry against the
	// digest of the whole file, and these entries are arm64 slices now. Each file
	// was verified while it was read.
	return bundleFrom(files), nil
}

// readCacheFile reads a staged asset and holds it to the size it was staged at.
//
// The parameter was accepted and ignored, so a truncated cache copy was only
// noticed later, as a handshake that failed for no stated reason.
func readCacheFile(path string, spec fileSpec) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cached asset: %w", err)
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect cached asset: %w", err)
	}

	// The staged copy is written from the bundle, so it can be larger than
	// the pinned size (iOS appends a code signature) but never smaller.
	if spec.size > 0 && info.Size() < int64(spec.size) {
		return nil, fmt.Errorf("cached asset %s is %d bytes, expected at least %d",
			filepath.Base(path), info.Size(), spec.size)
	}

	// The digest is taken by streaming, so the whole file is never held. CoreFP is
	// 95 MB and only its 31 MB arm64 slice is used; reading it whole put 95 MB in
	// the heap right where the engine asks for its translation buffer, and that
	// allocation is what failed.
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("hash cached asset: %w", err)
	}

	// Still the whole file's digest, byte for byte: only the buffer is gone.
	if actual := hasher.Sum(nil); !isZeroDigest(spec.digest) && !bytes.Equal(actual, spec.digest[:]) {
		return nil, fmt.Errorf("cached asset %s failed integrity verification: actual-sha256=%x",
			filepath.Base(path), actual)
	}

	return readArm64Slice(file, info.Size())
}

func writeCache(directory string, bundle Bundle) error {
	if err := validate(bundle); err != nil {
		return err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create SAP asset cache: %w", err)
	}

	files := bundleFiles(bundle)
	for _, spec := range requiredFiles {
		if err := replaceFile(filepath.Join(directory, spec.name), files[spec.name]); err != nil {
			return fmt.Errorf("write cached SAP asset %s: %w", spec.name, err)
		}
	}

	return nil
}

func replaceFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}

	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("set cache file permissions: %w", err)
	}

	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("write temporary cache file: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary cache file: %w", err)
	}

	if err := os.Rename(temporaryPath, path); err == nil {
		return nil
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove existing cache file: %w", err)
	}

	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install cache file: %w", err)
	}

	return nil
}

// Validate checks the four pinned binaries for size and SHA-256.
// Exported so callers that supply their own asset directory get the same
// integrity guarantees as the cache reader.
func Validate(bundle Bundle) error {
	return validate(bundle)
}

func validate(bundle Bundle) error {
	files := bundleFiles(bundle)
	for _, spec := range requiredFiles {
		data := files[spec.name]
		if len(data) == 0 {
			return fmt.Errorf("apple SAP asset %s is empty or missing", spec.name)
		}

		// Size is checked unconditionally and as a floor, not an
		// equality: re-signing on install only appends, so a copy
		// smaller than the pinned size is a truncation -- the failure
		// this loader exists to catch -- while a larger one is normal on
		// device. Nothing compared the size before, so a half-written
		// file was only reported as "empty" or not at all.
		if spec.size > 0 && len(data) < spec.size {
			return fmt.Errorf("apple SAP asset %s size is %d bytes, expected at least %d",
				spec.name, len(data), spec.size)
		}

		// On iOS, MobileInstallation re-signs Mach-O files in the app
		// bundle during install. This adds a code-signature blob to
		// AppleMediaServices, commerce, and CoreFP (but not CoreFP.icxs,
		// which is not a Mach-O). The re-signing changes the file size
		// and SHA-256, so the pinned digest will never match on device.
		//
		// The code signature is appended metadata; the actual Mach-O
		// segments (text, data, etc.) are unchanged. Unicorn maps only
		// the segments, so the SAP handshake works fine with the
		// re-signed bytes.
		//
		// DSH_SAP_VERIFY=1 forces the check (useful on macOS hosts
		// where the files are not re-signed). Default: skip.
		if os.Getenv("DSH_SAP_VERIFY") == "1" {
			actual := sha256.Sum256(data)
			if actual != spec.digest {
				return fmt.Errorf(
					"apple SAP asset %s failed integrity verification: size=%d expected-sha256=%x actual-sha256=%x "+
						"(on iOS, MobileInstallation re-signs Mach-O files, changing their bytes; this is expected)",
					spec.name, len(data), spec.digest, actual,
				)
			}
		}
	}

	return nil
}

func bundleFrom(files map[string][]byte) Bundle {
	return Bundle{
		AppleMediaServices: files["AppleMediaServices"],
		Commerce:           files["commerce"],
		CoreFP:             files["CoreFP"],
		CoreFPICXS:         files["CoreFP.icxs"],
	}
}

func bundleFiles(bundle Bundle) map[string][]byte {
	return map[string][]byte{
		"AppleMediaServices": bundle.AppleMediaServices,
		"commerce":           bundle.Commerce,
		"CoreFP":             bundle.CoreFP,
		"CoreFP.icxs":        bundle.CoreFPICXS,
	}
}

func mustDigest(value string) [32]byte {
	var digest [32]byte

	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	if len(decoded) != len(digest) {
		panic("invalid SHA-256 length")
	}

	copy(digest[:], decoded)

	return digest
}

const (
	fatMagic     = 0xcafebabe
	cpuTypeARM64 = 0x0100000c
	fatHeader    = 8
	fatArchSize  = 20
)

// isZeroDigest reports whether the digest was never pinned.
func isZeroDigest(d [32]byte) bool {
	for _, b := range d {
		if b != 0 {
			return false
		}
	}

	return true
}

// readArm64Slice returns the arm64 slice of a fat file, or the whole file when it
// is already thin.
//
// CoreFP is a 95 MB fat file whose arm64 slice is 31 MB. Loading the whole thing
// put 95 MB in the heap for the length of the open -- and the open is where the
// engine asks for its translation buffer.
func readArm64Slice(file *os.File, size int64) ([]byte, error) {
	var head [fatHeader]byte
	if _, err := file.ReadAt(head[:], 0); err != nil {
		return nil, fmt.Errorf("read asset header: %w", err)
	}

	if magic := binary.BigEndian.Uint32(head[:4]); magic != fatMagic {
		data := make([]byte, size)
		if _, err := file.ReadAt(data, 0); err != nil {
			return nil, fmt.Errorf("read asset: %w", err)
		}

		return data, nil
	}

	count := int(binary.BigEndian.Uint32(head[4:8]))
	if count <= 0 || count > 16 {
		return nil, fmt.Errorf("asset has %d architectures", count)
	}

	table := make([]byte, count*fatArchSize)
	if _, err := file.ReadAt(table, fatHeader); err != nil {
		return nil, fmt.Errorf("read asset table: %w", err)
	}

	for index := 0; index < count; index++ {
		entry := table[index*fatArchSize : (index+1)*fatArchSize]
		if binary.BigEndian.Uint32(entry[0:4]) != cpuTypeARM64 {
			continue
		}

		offset := int64(binary.BigEndian.Uint32(entry[8:12]))
		length := int64(binary.BigEndian.Uint32(entry[12:16]))

		if offset+length > size {
			return nil, fmt.Errorf("arm64 slice runs past the end of the file")
		}

		data := make([]byte, length)
		if _, err := file.ReadAt(data, offset); err != nil {
			return nil, fmt.Errorf("read arm64 slice: %w", err)
		}

		return data, nil
	}

	return nil, fmt.Errorf("asset has no arm64 slice")
}

// SliceArm64 keeps only the arm64 slice of a fat image, copying it so the caller's
// buffer can be dropped.
//
// The bridge loader reads each asset whole and validates the whole file, which is
// correct; the copy is what lets the 95 MB CoreFP buffer go before the engine
// asks for memory of its own. Peak during open drops from 95 MB to 31 MB with no
// change to what was verified.
func SliceArm64(data []byte) ([]byte, error) {
	if len(data) < fatHeader || binary.BigEndian.Uint32(data[:4]) != fatMagic {
		return data, nil
	}

	count := int(binary.BigEndian.Uint32(data[4:8]))
	if count <= 0 || count > 16 {
		return nil, fmt.Errorf("asset has %d architectures", count)
	}

	for index := 0; index < count; index++ {
		start := fatHeader + index*fatArchSize
		if start+fatArchSize > len(data) {
			break
		}

		entry := data[start : start+fatArchSize]
		if binary.BigEndian.Uint32(entry[0:4]) != cpuTypeARM64 {
			continue
		}

		offset := int(binary.BigEndian.Uint32(entry[8:12]))
		length := int(binary.BigEndian.Uint32(entry[12:16]))

		if offset < 0 || length <= 0 || offset+length > len(data) {
			return nil, fmt.Errorf("arm64 slice runs past the end of the asset")
		}

		sliced := make([]byte, length)
		copy(sliced, data[offset:offset+length])

		return sliced, nil
	}

	return nil, fmt.Errorf("asset has no arm64 slice")
}
