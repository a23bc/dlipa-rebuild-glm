//go:build (darwin && !ios) || linux

package unicorn

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/ebitengine/purego"
)

// unicornSearchPaths are the usual install locations for libunicorn 2.x.
var unicornSearchPaths = []string{
	"libunicorn.so.2",
	"libunicorn.so",
	"libunicorn.2.dylib",
	"libunicorn.dylib",
	"/usr/lib/libunicorn.so.2",
	"/usr/local/lib/libunicorn.so.2",
	"/opt/homebrew/lib/libunicorn.2.dylib",
	"/usr/local/lib/libunicorn.2.dylib",
}

// openLibrary loads a locally installed Unicorn. This trimmed build does not
// download Unicorn: iOS links it statically (library_ios.go) and desktop hosts
// are expected to install it themselves.
func openLibrary(ctx context.Context) (library, error) {
	if err := ctx.Err(); err != nil {
		return library{}, err
	}

	for _, candidate := range unicornSearchPaths {
		if candidate == "" {
			continue
		}
		handle, err := purego.Dlopen(candidate, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err == nil {
			return library{
				handle: handle,
				close: func() error {
					return purego.Dlclose(handle)
				},
			}, nil
		}
	}

	// Also honour an explicit override, useful for CI and local builds.
	if explicit := os.Getenv("DLIPA_UNICORN_PATH"); explicit != "" {
		handle, err := purego.Dlopen(explicit, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err == nil {
			return library{
				handle: handle,
				close: func() error {
					return purego.Dlclose(handle)
				},
			}, nil
		}
		return library{}, fmt.Errorf("open %s: %w", explicit, err)
	}

	return library{}, errors.New("libunicorn 2 not found; install it or set DLIPA_UNICORN_PATH")
}
