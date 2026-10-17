//go:build windows

package unicorn

import (
	"context"
	"errors"
)

// openLibrary is unavailable on Windows in this trimmed build. The iOS app
// links Unicorn statically (see library_ios.go); macOS and Linux load the
// shared library (library_unix.go).
func openLibrary(ctx context.Context) (library, error) {
	if err := ctx.Err(); err != nil {
		return library{}, err
	}
	return library{}, errors.New("unicorn is not available on windows; build for darwin, ios or linux")
}
