package storeauth

import (
	"context"
	"errors"
)

// StoreAMDHeaders is deliberately not implemented on this branch.
//
// Every measurement of the Store type-2 proof — this tree and the reference
// client — came back with "AppleMediaServices returned no Store AMD proof".
// The reference login survives that because it falls back to AnisetteHeaders
// when this call fails (appstore_native_login.go), and that fallback is the
// path that signed in on the bench at 11:28. Implementing the XPC adapter
// would be five hundred lines for a proof nothing has produced yet.
//
// The signature stays so the caller's fallback compiles and the branch can
// grow the real proof later without touching call sites.
func StoreAMDHeaders(_ context.Context, _ []byte, _ string, _ []byte) (map[string]string, []byte, error) {
	return nil, nil, errors.New("store AMD proof is not available on this branch")
}
