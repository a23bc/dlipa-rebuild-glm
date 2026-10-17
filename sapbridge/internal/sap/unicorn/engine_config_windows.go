//go:build windows

package unicorn

// configureEngine is a no-op on Windows in this trimmed build; the CPU model
// selection in engine.New already fails earlier because openLibrary does.
func configureEngine(*Engine) error {
	return nil
}
