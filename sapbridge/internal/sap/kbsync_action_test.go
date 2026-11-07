package sap

import "testing"

// TestDecideBlobActionKeepsTheBlobThroughAccountAnswers pins the failure that
// reached a device: a version-history lookup for an app the account does not
// own answers 9610, and the old condition read any failure as a refused blob,
// so the account's cached kbsync was deleted by reading a list. The next
// download then had no blob and could not generate one with a store session
// open, which only a restart cleared.
func TestDecideBlobActionKeepsTheBlobThroughAccountAnswers(t *testing.T) {
	t.Parallel()

	// Licence and session answers, each seen in this field on device.
	for _, failureType := range []string{"9610", "5002", "2042", "2034", "2002", "signInRequired", "passwordTokenExpired"} {
		if got := decideBlobAction(failureType, true); got != actionKept {
			t.Errorf("failureType %s from a cached blob: got %v, want the blob kept", failureType, got)
		}
	}

	if got := decideBlobAction("", true); got != actionUnchanged {
		t.Errorf("a successful answer should not touch the blob: got %v", got)
	}

	// The self-heal stays for codes this list does not know: a value Apple has
	// refused must not be replayed forever. It has to be a code the account
	// answers do not explain, which is why the discard prints it.
	if got := decideBlobAction("9613", true); got != actionDiscard {
		t.Errorf("an unknown failure on a cached blob should discard it: got %v", got)
	}

	if got := decideBlobAction("9613", false); got != actionNothingStored {
		t.Errorf("an unknown failure on a generated blob has no cached copy to lose: got %v", got)
	}
}
