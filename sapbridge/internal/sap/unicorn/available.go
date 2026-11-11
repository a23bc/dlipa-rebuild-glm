package unicorn

import "context"

// Available reports whether this host can load a usable libunicorn 2 at all.
//
// The live tests ask this before they spend anything, because the question
// they answer needs the emulator: a checkout without the shared object fails
// whatever else is true, and fetching the pinned Apple assets first -- minutes
// of download in a job that can never use them -- reports the wrong thing as
// the interesting number. It opens and closes the library rather than starting
// an engine, which is the whole of what is being asked.
func Available() bool {
	found, err := openLibrary(context.Background())
	if err != nil {
		return false
	}

	if found.close != nil {
		// A library that dlopens but will not dlclose is still one this
		// process can run, so the close result is not the answer here.
		_ = found.close()
	}

	return true
}
