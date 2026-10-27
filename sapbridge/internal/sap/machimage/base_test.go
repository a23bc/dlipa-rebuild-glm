package machimage

import (
	"debug/macho"
	"os"
	"testing"
)

// The preferred load address of the arm64 slice: the lowest vmaddr among the
// segments. Compare with coreFPBase (0x100000000000), which is where the machine
// actually puts it.
func TestCoreFPSegmentVMAddrs(t *testing.T) {
	data, err := os.ReadFile("../../../../VendorAssets/CoreFP")
	if err != nil {
		t.Skipf("asset not present: %v", err)
	}

	fat, err := macho.NewFatFile(bytesReaderAt(data))
	if err != nil {
		t.Fatalf("fat: %v", err)
	}

	for _, arch := range fat.Arches {
		if arch.Cpu != macho.CpuArm64 {
			continue
		}
		first := true
		var low uint64
		for _, load := range arch.File.Loads {
			seg, ok := load.(*macho.Segment)
			if !ok || seg.Name == "__PAGEZERO" {
				continue
			}
			if first || seg.Addr < low {
				low = seg.Addr
				first = false
			}
			t.Logf("seg %-12s addr=%#x size=%#x", seg.Name, seg.Addr, seg.Memsz)
		}
		t.Logf("lowest segment vmaddr = %#x   (coreFPBase = 0x100000000000)", low)
	}
}
