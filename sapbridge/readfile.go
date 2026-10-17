package sapbridge

import (
	"os"
	"syscall"
)

// readFile reads a file into a byte slice. On Unix-like systems (iOS,
// macOS, Linux) it uses mmap instead of read(2) so the kernel pages
// the file in on demand rather than allocating heap upfront.
//
// Why: the SAP assets are 126 MB total (CoreFP 95 MB + AppleMediaServices
// 15 MB + commerce 8 MB + CoreFP.icxs 7 MB). os.ReadFile allocates 126 MB
// of Go heap immediately. Under iOS's tight per-process virtual address
// ceiling, that 126 MB plus Unicorn's mmap requests cause "Could not
// allocate dynamic translator buffer". With mmap, the file pages are
// mapped copy-on-write; untouched pages share the kernel page cache
// (no RSS cost), and only pages we write to (PAC removal, fixups)
// become private copies.
//
// The returned slice is backed by the mmap. machimage.Open writes to
// it for pointer-authentication removal and chained-fixup rewrites;
// PROT_WRITE is required or those writes segfault. The mapping stays
// alive for the process's lifetime; we do not munmap.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size <= 0 {
		return []byte{}, nil
	}

	// mmap the whole file with MAP_PRIVATE + PROT_READ|PROT_WRITE.
	// MAP_PRIVATE means copy-on-write: untouched pages share the
	// kernel's file page cache (no RSS cost), and only pages we
	// actually write to (PAC instruction removal, fixup patching)
	// become private copies. This keeps RSS far below the 126 MB
	// that os.ReadFile would allocate upfront.
	//
	// machimage.Open writes to i.data (PutUint32 for PAC removal,
	// PutUint64 for chained-fixup rewrites); PROT_WRITE is required
	// or those writes will segfault.
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE)
	if err != nil {
		// Fall back to os.ReadFile if mmap fails (e.g. on a pipe
		// or special file that can't be mmap'd).
		return os.ReadFile(path)
	}

	// Touch the first byte to force the kernel to fault in the first
	// page now — surfaces any permission/access error early instead of
	// at a random access inside Unicorn.
	_ = data[0]

	return data, nil
}
