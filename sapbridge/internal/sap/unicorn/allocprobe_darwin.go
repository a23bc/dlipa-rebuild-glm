//go:build darwin

package unicorn

import (
	"fmt"
	"syscall"
)

// probeTranslationAlloc tries the allocation Unicorn is about to make and
// reports what the kernel says.
//
// The failure we are chasing prints "Could not allocate dynamic translator
// buffer" and exits, with no errno. The comment on tcgBufferSizeIOS claims the
// Unicorn patch prints one, but no run has ever shown it, so the number is
// measured here instead: same size, same flags, same process, immediately before
// QEMU asks for it.
//
// Two variants are tried because they fail for different reasons: an anonymous
// mapping with PROT_EXEC is refused outright on a device that does not allow
// executable memory, while one without it fails only when the address space or
// the commit limit is exhausted. Which of the two succeeds says which problem
// this is.
func probeTranslationAlloc(size int) string {
	withExec, execErr := tryMap(size, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	withoutExec, plainErr := tryMap(size, syscall.PROT_READ|syscall.PROT_WRITE)

	switch {
	case withExec == "" && withoutExec == "":
		return fmt.Sprintf("%d MiB: rwx ok, rw ok", size>>20)
	case withExec == "" && withoutExec != "":
		return fmt.Sprintf("%d MiB: rwx ok, rw failed (%s)", size>>20, withoutExec)
	case withExec != "" && withoutExec == "":
		return fmt.Sprintf("%d MiB: rwx failed (%s), rw ok", size>>20, withExec)
	default:
		return fmt.Sprintf("%d MiB: rwx failed (%s), rw failed (%s)", size>>20, execErr, plainErr)
	}
}

// tryMap returns an empty string on success and the errno on failure.
func tryMap(size int, prot int) (string, string) {
	memory, err := syscall.Mmap(-1, 0, size, prot, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return errnoText(err), errnoText(err)
	}

	_ = syscall.Munmap(memory)

	return "", ""
}

func errnoText(err error) string {
	if errno, ok := err.(syscall.Errno); ok {
		// The number is what matters: ENOMEM and EINVAL point at different
		// problems, and the name alone has been misread before.
		return fmt.Sprintf("errno %d %s", int(errno), errno.Error())
	}

	return err.Error()
}
