package emulator

import "testing"

// Close hands the address space back, with three exceptions: the heap, the stack
// and the return stub are at fixed addresses the SAP machine also uses, and it
// allocates from the heap for the life of the process. Releasing any of them
// leaves the signer pointing at memory the engine no longer has, and the failure
// would not show up until the next signature.
func TestSharedWithMachineKeepsTheFixedRegions(t *testing.T) {
	kept := []struct {
		name string
		page uint64
	}{
		{"heap base", heapBase},
		{"heap tail", heapBase + heapSize - 4096},
		{"stack base", stackBase},
		{"stack tail", stackBase + stackSize - 4096},
		{"return stub", returnPC},
	}

	for _, test := range kept {
		if !sharedWithMachine(test.page) {
			t.Errorf("%s at %#x must survive Close", test.name, test.page)
		}
	}

	// Everything just outside them belongs to the runtime: releasing it is what
	// makes a second open possible at all.
	released := []struct {
		name string
		page uint64
	}{
		{"below the heap", heapBase - 4096},
		{"above the heap", heapBase + heapSize},
		{"below the stack", stackBase - 4096},
		{"above the stack", stackBase + stackSize},
		{"after the stub", returnPC + 4096},
		{"a profile page", 0x1a241f000},
	}

	for _, test := range released {
		if sharedWithMachine(test.page) {
			t.Errorf("%s at %#x must be released on Close", test.name, test.page)
		}
	}
}
