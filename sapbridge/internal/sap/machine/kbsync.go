package machine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/unicorn"
)

// kbsyncStep runs one step of a kbsync generation and stamps what it cost: wall
// time, how many times the guest had to be started, and how many instructions the
// arm64 compatibility layer emulated here in Go rather than letting the engine run
// them.
//
// The three belong on the same line because the total has never been readable on
// its own: this path measured 35 s and 117 s on device with nothing printed inside
// either, and a wall number alone cannot tell "the guest ran a lot of code" from
// "the guest ran a little code, and we interpret it in Go between engine starts".
// Those have different fixes, and the second one is the only lever that has ever
// moved an emulation cost here.
//
// The step is stamped whether it succeeded or not: a generation that dies says
// which step killed it, which is the same question the timing answers.
//
// Both counters are process-global, not per-machine -- the store runtime's faults
// increment them too. That is safe here and nowhere else: every caller holds the
// signer's mutex across a kbsync, and nothing on that lock runs the other guest at
// the same time.
func (m *Machine) kbsyncStep(name string, fn func() error) error {
	start := time.Now()
	startsBefore := unicorn.EmuStarts()
	handledBefore := m.arm64Handled

	err := fn()

	kbsyncStamp(name, start, unicorn.EmuStarts()-startsBefore, m.arm64Handled-handledBefore)

	return err
}

// kbsyncBytes is kbsyncStep for the step that hands back the blob.
func (m *Machine) kbsyncBytes(name string, fn func() ([]byte, error)) ([]byte, error) {
	start := time.Now()
	startsBefore := unicorn.EmuStarts()
	handledBefore := m.arm64Handled

	blob, err := fn()

	kbsyncStamp(name, start, unicorn.EmuStarts()-startsBefore, m.arm64Handled-handledBefore)

	return blob, err
}

// kbsyncStamp prints what kbsyncStep measured. It is split out because the
// second-emulator path cannot use the method: there is no machine to read the
// compatibility counter from until the emulator is already open.
func kbsyncStamp(name string, start time.Time, starts, handled uint64) {
	fmt.Fprintf(os.Stderr, "[SAP] kbsync: %s in %s (%d emulation starts, %d instructions emulated in Go)\n",
		name, time.Since(start).Round(time.Millisecond), starts, handled)
}

// GenerateKBSync creates the account and hardware bound FairPlay data required
// by the bag's ent/download endpoint, without opening a decryption session.
func GenerateKBSync(ctx context.Context, bundle assets.Bundle, hardwareID []byte, dsid uint64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("StoreAgent context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate kbsync: %w", err)
	}

	if dsid == 0 {
		return nil, errors.New("kbsync requires a nonzero account DSID")
	}

	openStart := time.Now()
	openStarts := unicorn.EmuStarts()

	agent, globalContext, err := openStoreAgentGlobal(ctx, bundle, hardwareID)
	if err != nil {
		return nil, err
	}
	defer agent.Close()

	// The machine here is brand new inside openStoreAgentGlobal, so its lifetime
	// count is the delta for this step. The other two call sites read deltas
	// because their machine outlives the call.
	kbsyncStamp("open storeagent", openStart, unicorn.EmuStarts()-openStarts, agent.guest.arm64Handled)

	return agent.guest.kbsyncBytes("generate", func() ([]byte, error) {
		return agent.guest.generateKBSync(storeAgentKBSyncEntry, globalContext, dsid)
	})
}

func (m *Machine) generateKBSync(entry uint64, globalContext uint32, dsid uint64) ([]byte, error) {
	m.beginCall()
	defer m.clearScratch()

	pointerField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, err
	}

	// StoreAgent writes a uint32 length. Zero the upper half so consumeOutput
	// can share the SAP buffer bounds checking and storage disposal.
	lengthField, err := m.scratch(nil, 8)
	if err != nil {
		return nil, err
	}

	status, err := m.invoke(entry, uint64(globalContext), dsid, 0, 1, pointerField, lengthField)
	if err != nil {
		return nil, fmt.Errorf("generate StoreAgent kbsync: %w", err)
	}

	output, outputErr := m.consumeOutput(pointerField, lengthField)
	if int32(status) != 0 {
		return nil, errors.Join(fmt.Errorf("StoreAgent kbsync returned %d", int32(status)), outputErr)
	}

	if outputErr != nil {
		return nil, outputErr
	}

	if len(output) == 0 {
		return nil, errors.New("StoreAgent kbsync returned an empty buffer")
	}

	return output, nil
}
