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

	// The default, in case the size control never landed and QEMU is still asking
	// for what Unicorn ships with. A 4 MiB request succeeding while QEMU fails is
	// exactly that situation: the kernel is willing, the request is not 4 MiB.
	const defaultSize = 1 << 30
	defaultResult := trySize(defaultSize)

	switch {
	case withExec == "" && withoutExec == "":
		return fmt.Sprintf("%d MiB: rwx ok, rw ok; default %s", size>>20, defaultResult)
	case withExec == "" && withoutExec != "":
		return fmt.Sprintf("%d MiB: rwx ok, rw failed (%s); default %s", size>>20, withoutExec, defaultResult)
	case withExec != "" && withoutExec == "":
		return fmt.Sprintf("%d MiB: rwx failed (%s), rw ok; default %s", size>>20, withExec, defaultResult)
	default:
		return fmt.Sprintf("%d MiB: rwx failed (%s), rw failed (%s); default %s",
			size>>20, execErr, plainErr, defaultResult)
	}
}

// tryMap returns an empty string on success and the errno on failure.
// trySize reports how a request for this size fares, in one line.
func trySize(size int) string {
	exec, plain := tryMap(size, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	if exec == "" && plain == "" {
		return fmt.Sprintf("%d MiB: ok", size>>20)
	}

	return fmt.Sprintf("%d MiB: rwx %q rw %q", size>>20, exec, plain)
}

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
