package emulator

// The profile tables are generated data, so their shapes live in the format
// package and are aliased here rather than duplicated. Keeping the alias names
// identical to upstream is deliberate: it lets the rest of the emulator port be a
// straight copy, so any future upstream diff shows only real changes.

import (
	profileformat "github.com/a23bc/dlipa-rebuild/sapbridge/internal/store/profile/format"
)

type Method = profileformat.Method
type Class = profileformat.Class
type Call = profileformat.Call
type Page = profileformat.Page
type Constant = profileformat.Constant
type DictionaryLayout = profileformat.DictionaryLayout
type MetadataPatch = profileformat.MetadataPatch
type Profile = profileformat.Profile

type Object struct {
	Class      string
	Value      any
	Properties map[string]uint64
}

// Guest layout constants, copied from upstream runtime.go. heapSize bounds every
// allocation the bridge makes inside the guest, so it belongs with the types
// rather than with the guest setup that will arrive with the rest of the port.
const (
	heapBase = uint64(0x300000000)
	heapSize = uint64(64 << 20)
	stackBase = uint64(0x500000000000)
	stackSize = uint64(8 << 20)
	returnPC  = uint64(0x100000000)
)

// methodKey names a method the way the bridge looks it up: sign, class, selector.
// Copied from upstream runtime.go so the rest of the port needs no edits.
func methodKey(class, selector string, meta bool) string {
	prefix := "-"
	if meta {
		prefix = "+"
	}

	return prefix + "[" + class + " " + selector + "]"
}

// Runtime is deliberately small for now: only the fields runtimeMetadata.newRuntime
// populates. The engine, guest state and bridge fields arrive with the rest of
// the port, and keeping this minimal means the metadata step compiles and is
// testable without dragging any of that in.
type Runtime struct {
	profile           Profile
	classes           map[string]*Class
	classNames        map[uint64]string
	methods           map[string]uint64
	calls             map[uint64]Call
	selectors         map[uint64]string
	selectorAddresses map[string]uint64
	objects           map[uint64]*Object
	entries           map[uint64]string
	pages             map[uint64]bool
}
