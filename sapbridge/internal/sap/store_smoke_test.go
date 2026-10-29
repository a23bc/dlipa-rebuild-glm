package sap

import (
	"errors"
	"testing"
	"time"
)

// TestSignLockedDoesNotTakeTheLock pins the contract that broke a device run.
//
// StoreSmoke holds s.mu for its whole run and signs inside it as a probe. It
// used to call Sign, which takes the same mutex, and sync.Mutex is not
// reentrant: the run stopped printing after the image line with no error and no
// crash. A caller that holds the lock must be able to call signLocked and get an
// answer.
func TestSignLockedDoesNotTakeTheLock(t *testing.T) {
	signer := &Signer{closed: true}

	signer.mu.Lock()

	done := make(chan error, 1)

	go func() {
		_, err := signer.signLocked(nil)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errSignerClosed) {
			signer.mu.Unlock()

			t.Fatalf("signLocked returned %v, want errSignerClosed", err)
		}
	case <-time.After(2 * time.Second):
		signer.mu.Unlock()

		t.Fatal("signLocked blocked: it must not take the lock its caller already holds")
	}

	signer.mu.Unlock()
}
