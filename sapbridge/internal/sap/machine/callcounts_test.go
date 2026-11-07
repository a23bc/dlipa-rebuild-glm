package machine

import "testing"

// TestSetCallCountingRestoresWhatItFound guards the switch's contract. Counting
// costs a mutex and a map write on every service call the guest makes, which is
// why it is off by default -- so a measurement that finishes must leave the
// process exactly as it found it, including when another measurement is already
// running inside it.
func TestSetCallCountingRestoresWhatItFound(t *testing.T) {
	if CallCounting() {
		t.Fatal("counting has to be off until a caller asks for it")
	}

	previous := SetCallCounting(true)

	if previous || !CallCounting() {
		t.Fatalf("turning counting on reported the previous value as %v", previous)
	}

	nested := SetCallCounting(true)

	if !nested {
		t.Fatal("the nested call lost the state it was asked to restore")
	}

	SetCallCounting(nested)

	if !CallCounting() {
		t.Fatal("restoring the nested value turned counting off while the outer caller still wanted it")
	}

	SetCallCounting(previous)

	if CallCounting() {
		t.Fatal("the outer caller did not restore the process to off")
	}
}

// TestRecordExternalCallAggregatesPerService guards the shape the dlopen question
// is read off: one entry per symbol, counts summed, most-called first. A report
// that keyed per call site, or that came out in map order, would answer a
// different question than the one the numbers are used for.
func TestRecordExternalCallAggregatesPerService(t *testing.T) {
	ResetExternalCalls()
	t.Cleanup(ResetExternalCalls)

	recordExternalCall("_x")
	recordExternalCall("_x")
	recordExternalCall("_y")

	got := ExternalCalls()

	if len(got) != 2 {
		t.Fatalf("want one entry per service, got %d: %+v", len(got), got)
	}

	if got[0].Name != "_x" || got[0].Count != 2 {
		t.Fatalf("_x aggregated or ordered wrong: %+v", got[0])
	}

	if got[1].Name != "_y" || got[1].Count != 1 {
		t.Fatalf("_y aggregated or ordered wrong: %+v", got[1])
	}
}
