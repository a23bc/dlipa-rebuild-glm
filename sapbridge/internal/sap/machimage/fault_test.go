package machimage

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestDecodeFaultWindow(t *testing.T) {
	const path = "../../../../VendorAssets/AppleMediaServices"

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("asset not present: %v", err)
	}

	const fault = 0x1a2af078c
	const textAddr = 0x1a241d000

	base := uint64(fault - 32)

	for i := uint64(0); i < 80; i += 4 {
		addr := base + i
		off := int64(addr - textAddr)
		word := binary.LittleEndian.Uint32(raw[off:])

		mark := " "
		if addr == fault {
			mark = ">"
		}

		t.Logf("%s %#x: %#08x", mark, addr, word)
	}
}
