//go:build !darwin

package unicorn

// probeTranslationAlloc only runs where the allocation happens.
func probeTranslationAlloc(size int) string { return "" }
