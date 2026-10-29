//go:build !unix

package sapbridge

import "os"

// readFile reads a file into a byte slice.
//
// Windows has no syscall.Mmap, so there is nothing to map: os.ReadFile is the
// only option and the 126 MB the Unix path avoids becomes a real allocation.
// That costs the Windows build nothing that matters -- it exists so the package
// compiles and its tests run on the platform the project is developed on, not
// because the signer is expected to work there.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
