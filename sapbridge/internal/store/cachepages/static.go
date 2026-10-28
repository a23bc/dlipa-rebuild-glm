package cachepages

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed static-pages.txt
var staticList string

// StaticPages reports the shared-cache pages the vendored images point at.
//
// These are not derivable from the profile. The profile is a snapshot of dynamic
// state, so its pages only reveal pointers the process happened to hold; a
// pointer compiled into a data segment is invisible to that scan. That gap is
// what kept initWithBag failing after the first page blob shipped: the slot at
// 0x1e660ae58 in AppleMediaServices' __DATA_DIRTY points at 0x1e9881478, and no
// profile page had ever mentioned the page holding it.
//
// The list is generated from VendorAssets by static_test.go and committed so the
// page export does not need the images on the runner.
func StaticPages() []uint64 { return parsePageList(staticList) }

// parsePageList reads one address per line, ignoring comments and blank lines.
// Shared with ExtraPages, whose file has the same shape.
func parsePageList(text string) []uint64 {
	var out []uint64

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0x") {
			continue
		}

		value, err := strconv.ParseUint(line[2:], 16, 64)
		if err != nil {
			continue
		}

		out = append(out, value)
	}

	return out
}
