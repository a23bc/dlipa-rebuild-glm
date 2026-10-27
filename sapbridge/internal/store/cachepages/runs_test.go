package cachepages

import "testing"

// Grouping pages must not move a byte: the guest maps the runs instead of the
// pages, so anything the grouping gets wrong shows up as corrupted cache data
// far away from here.
func TestRunsPreserveTheBlob(t *testing.T) {
	pages, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if len(pages) == 0 {
		t.Skip("no page blob in this build")
	}

	runs := Runs(pages)
	if len(runs) == 0 {
		t.Fatal("no runs")
	}

	if len(runs) >= len(pages) {
		t.Fatalf("%d runs for %d pages: nothing was grouped", len(runs), len(pages))
	}

	var total int

	for index, run := range runs {
		if run.Address&0xFFF != 0 {
			t.Fatalf("run %d at %#x is not page aligned", index, run.Address)
		}

		if len(run.Data) == 0 || len(run.Data)%4096 != 0 {
			t.Fatalf("run %d at %#x holds %d bytes", index, run.Address, len(run.Data))
		}

		if index > 0 {
			previous := runs[index-1]
			if previous.Address+uint64(len(previous.Data)) >= run.Address {
				t.Fatalf("runs %d and %d overlap or touch: %#x then %#x", index-1, index,
					previous.Address, run.Address)
			}
		}

		total += len(run.Data)
	}

	var want int
	for _, page := range pages {
		want += len(page.Data)
	}

	if total != want {
		t.Fatalf("runs carry %d bytes, pages carry %d", total, want)
	}

	// Every page must still be readable at its own address.
	index := 0

	for _, page := range pages {
		for index < len(runs) && runs[index].Address <= page.Address {
			index++
		}

		run := runs[index-1]
		offset := page.Address - run.Address

		if offset+4096 > uint64(len(run.Data)) {
			t.Fatalf("page %#x is not inside run %#x", page.Address, run.Address)
		}

		if string(run.Data[offset:offset+4096]) != string(page.Data) {
			t.Fatalf("page %#x differs from the bytes in its run", page.Address)
		}
	}

	t.Logf("%d pages grouped into %d runs", len(pages), len(runs))
}
