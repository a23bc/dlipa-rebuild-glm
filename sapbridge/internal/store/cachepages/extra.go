package cachepages

import _ "embed"

//go:embed extra-pages.txt
var extraList string

// ExtraPages reports shared-cache pages that neither derived set can reach.
//
// The blob is built from two scans: pointers held in the profile's prepared
// pages, and pointers compiled into the vendored images. Both read data. Signing
// failed because AMS does not: it computes its target out of an obfuscated table,
// so 0x1880de740 is reached from the shipped page 0x180889c28 while appearing in
// no scan of anything.
//
// This list is therefore maintained by hand, one fault at a time, and it is a
// window rather than the single page that faulted: the page carries the function
// entry but not the functions it calls, and each of those would otherwise cost
// its own regeneration. See extra-pages.txt for the current window and why it is
// that size.
func ExtraPages() []uint64 { return parsePageList(extraList) }
