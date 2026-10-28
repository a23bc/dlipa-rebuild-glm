package cachepages

import _ "embed"

//go:embed extra-pages.txt
var extraList string

//go:embed required-pages.txt
var requiredList string

// ExtraPages reports shared-cache pages that neither derived set can reach.
//
// The blob is built from two scans: pointers held in the profile's prepared
// pages, and pointers compiled into the vendored images. Both read data. Signing
// failed because AMS does not: it computes its target out of an obfuscated table,
// so 0x1880de740 is reached from the shipped page 0x180889c28 while appearing in
// no scan of anything.
//
// This list is therefore maintained by hand, one fault at a time, and it is a
// window rather than the single page that faulted: a page brings the function
// entry but not the functions it calls, and each of those would otherwise cost
// its own regeneration.
//
// Entries here may name pages the pinned cache does not have. That is why the
// hard check is RequiredPages: a window is an attempt, and part of it landing
// outside the cache is information, not a failure.
func ExtraPages() []uint64 { return parsePageList(extraList) }

// RequiredPages reports the explored pages that must survive into the blob.
func RequiredPages() []uint64 { return parsePageList(requiredList) }
