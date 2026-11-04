package install

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// blankAudio is the silent track the keep-alive plays.
//
// It is embedded rather than shipped as a bundle resource: the project's resource
// phase did not pick the file up, and a keep-alive that silently falls back to a
// synthesised track is worse than carrying 300 KB in the binary.
//
//go:embed blank_audio.mp3
var blankAudio []byte

// BlankAudioPath writes the track to the cache directory and returns its path,
// because AVAudioPlayer wants a URL.
func BlankAudioPath(dataDir string) (string, error) {
	if len(blankAudio) == 0 {
		return "", fmt.Errorf("install: no blank audio embedded")
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", fmt.Errorf("install: audio dir: %w", err)
	}

	path := filepath.Join(dataDir, "blank_audio.mp3")

	// Written once: the bytes never change, and rewriting 300 KB on every install
	// would be work for nothing.
	if existing, err := os.Stat(path); err == nil && existing.Size() == int64(len(blankAudio)) {
		return path, nil
	}

	if err := os.WriteFile(path, blankAudio, 0o600); err != nil {
		return "", fmt.Errorf("install: write audio: %w", err)
	}

	return path, nil
}
