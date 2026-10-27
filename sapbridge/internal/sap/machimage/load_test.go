package machimage

import (
	"encoding/binary"
	"os"
	"testing"
)

// recordingMemory keeps what Load wrote, so a segment that was mapped but never
// filled can be told apart from one that was never mapped.
type recordingMemory struct {
	mapped map[uint64]uint64
	writes map[uint64][]byte
}

func newRecordingMemory() *recordingMemory {
	return &recordingMemory{mapped: map[uint64]uint64{}, writes: map[uint64][]byte{}}
}

func (m *recordingMemory) MemMap(address, size uint64) error {
	m.mapped[address] = size

	return nil
}

func (m *recordingMemory) MemWrite(address uint64, data []byte) error {
	m.writes[address] = append([]byte(nil), data...)

	return nil
}

// read returns the bytes Load placed at address, if any write covers it.
func (m *recordingMemory) read(address uint64, size int) ([]byte, bool) {
	for start, data := range m.writes {
		if address < start || address+uint64(size) > start+uint64(len(data)) {
			continue
		}

		offset := address - start

		return data[offset : offset+uint64(size)], true
	}

	return nil, false
}

// TestLoadFillsEveryMappedSegment is the guard for __DATA_DIRTY.
//
// That segment was mapped and then skipped when writing, so the guest read a
// zero page where the file holds a pointer. initWithBag stopped there: the slot
// at 0x1e660ae58 held 0 instead of 0x1e9881478, and the next load through it
// faulted on address 0x50.
func TestLoadFillsEveryMappedSegment(t *testing.T) {
	raw, err := os.ReadFile(amsAsset)
	if err != nil {
		t.Skipf("asset not present: %v", err)
	}

	image, err := Open("AppleMediaServices", raw)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err = image.PreparePrelinked(nil, func(symbol string) (uint64, error) {
		return 0, nil
	}); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	memory := newRecordingMemory()
	if err = image.Load(memory); err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, item := range image.segments {
		if item.name == "__PAGEZERO" || item.name == "__LINKEDIT" || item.fileSize == 0 {
			continue
		}

		if _, ok := memory.read(item.address, 8); !ok {
			t.Fatalf("%s at %#x was mapped but never written", item.name, item.address)
		}
	}

	// The slot the fault read: file says a pointer, guest must say the same.
	const slot = 0x1e660ae58

	data, ok := memory.read(slot, 8)
	if !ok {
		t.Fatalf("no write covers %#x", slot)
	}

	got := binary.LittleEndian.Uint64(data)
	if got == 0 {
		t.Fatalf("%#x is zero in the guest; the segment was not written", slot)
	}

	t.Logf("%#x = %#x", slot, got)
}
