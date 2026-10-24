package machine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/a23bc/dlipa-rebuild/sapbridge/internal/sap/assets"
)

const (
	storeAgentBase         = uint64(0x00001000c0000000)
	storeAgentGlobalInit   = storeAgentBase + 0x1312fc
	storeAgentKBSyncEntry  = storeAgentBase + 0x19ae34
	storeAgentSessionInit  = storeAgentBase + 0x13ac60
	storeAgentDecryptEntry = storeAgentBase + 0x175390
	storeAgentGlobalClose  = storeAgentBase + 0x130eb4
	storeAgentChunkSize    = 0x8000
	storeAgentSCInfoPath   = "/Users/Shared/SC Info"
)

var storeAgentZeroReturnAliases = []string{
	"_pthread_rwlock_rdlock",
	"_pthread_rwlock_rdlock$UNIX2003",
	"_pthread_mutex_init",
	"_pthread_mutex_destroy",
	"_pthread_rwlock_destroy",
}

type StoreAgent struct {
	mu           sync.Mutex
	guest        *Machine
	global       uint32
	session      uint64
	decryptEntry uint64
	closeEntry   uint64
	closed       bool
}

func OpenStoreAgent(ctx context.Context, bundle assets.Bundle, hardwareID, dpInfo []byte) (*StoreAgent, error) {
	if ctx == nil {
		return nil, errors.New("StoreAgent context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open StoreAgent runtime: %w", err)
	}

	return openStoreAgent(ctx, bundle, hardwareID, dpInfo)
}

func openStoreAgent(ctx context.Context, bundle assets.Bundle, hardwareID, dpInfo []byte) (*StoreAgent, error) {
	if len(dpInfo) == 0 {
		return nil, errors.New("StoreAgent dpInfo is empty")
	}

	agent, globalContext, err := openStoreAgentGlobal(ctx, bundle, hardwareID)
	if err != nil {
		return nil, err
	}

	agent.session, err = agent.initializeSession(globalContext, dpInfo)
	if err != nil {
		_ = agent.Close()

		return nil, err
	}

	return agent, nil
}

func openStoreAgentGlobal(ctx context.Context, bundle assets.Bundle, hardwareID []byte) (*StoreAgent, uint32, error) {
	if ctx == nil {
		return nil, 0, errors.New("StoreAgent context is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("open StoreAgent runtime: %w", err)
	}

	hardware, err := hardwareBlock(hardwareID)
	if err != nil {
		return nil, 0, err
	}

	guest, exports, err := openRuntime(ctx, bundle, runtimeOptions{
		extraImages: []imageSpec{{name: "commerce", data: bundle.Commerce, base: storeAgentBase}},
		shims: shimOptions{
			zeroReturnAliases: storeAgentZeroReturnAliases,
		},
	})
	if err != nil {
		return nil, 0, fmt.Errorf("start StoreAgent runtime: %w", err)
	}

	guest.entry.dispose = exports["_jEHf8Xzsv8K"]

	agent := &StoreAgent{
		guest:        guest,
		decryptEntry: storeAgentDecryptEntry,
		closeEntry:   storeAgentGlobalClose,
	}

	globalContext, err := agent.initializeGlobal(hardware)
	if err != nil {
		_ = agent.Close()

		return nil, 0, err
	}

	agent.global = globalContext

	return agent, globalContext, nil
}

func (s *StoreAgent) initializeGlobal(hardware []byte) (uint32, error) {
	return s.guest.initializeStoreAgentGlobal(hardware)
}

// initializeStoreAgentGlobal runs commerce's global constructor and returns the
// context handle it produced.
//
// It lives on Machine, not StoreAgent, so a machine that is already open can be
// used for kbsync without a second emulator being created.
func (m *Machine) initializeStoreAgentGlobal(hardware []byte) (uint32, error) {
	m.beginCall()
	defer m.clearScratch()

	hardwareAddress, err := m.scratch(hardware, uint64(len(hardware)))
	if err != nil {
		return 0, err
	}

	path := append([]byte(storeAgentSCInfoPath), 0)
	pathAddress, err := m.scratch(path, uint64(len(path)))

	if err != nil {
		return 0, err
	}

	contextField, err := m.scratch(nil, 4)
	if err != nil {
		return 0, err
	}

	status, err := m.invoke(m.storeAgent.globalInit, 0, hardwareAddress, pathAddress, contextField)
	if err != nil {
		return 0, fmt.Errorf("initialize StoreAgent global context: %w", err)
	}

	if int32(status) != 0 {
		return 0, fmt.Errorf("StoreAgent global initialization returned %d", int32(status))
	}

	value, err := m.readUint32(contextField)
	if err != nil {
		return 0, err
	}

	if value == 0 {
		return 0, errors.New("StoreAgent global initialization returned a null context")
	}

	return value, nil
}

// closeStoreAgentGlobal releases a context from initializeStoreAgentGlobal.
func (m *Machine) closeStoreAgentGlobal(global uint32) error {
	if global == 0 {
		return nil
	}

	status, err := m.invoke(m.storeAgent.globalClose, uint64(global))
	if err != nil {
		return fmt.Errorf("close StoreAgent global context: %w", err)
	}

	if int32(status) != 0 {
		return fmt.Errorf("StoreAgent global context close returned %d", int32(status))
	}

	return nil
}

// GenerateKBSyncOn produces the FairPlay blob on an already-open machine.
//
// This is the form the app uses. It used to call GenerateKBSync, which opened a
// whole second emulator; on iOS the second one cannot be created at all while
// the first is resident, and the failure is an exit(1) inside QEMU that leaves no
// trace but the last stderr line.
func GenerateKBSyncOn(ctx context.Context, m *Machine, hardwareID []byte, dsid uint64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("StoreAgent context is nil")
	}

	if m == nil {
		return nil, errors.New("StoreAgent machine is nil")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("generate kbsync: %w", err)
	}

	if dsid == 0 {
		return nil, errors.New("kbsync requires a nonzero account DSID")
	}

	hardware, err := hardwareBlock(hardwareID)
	if err != nil {
		return nil, err
	}

	global, err := m.initializeStoreAgentGlobal(hardware)
	if err != nil {
		return nil, err
	}
	defer func() { _ = m.closeStoreAgentGlobal(global) }()

	return m.generateKBSync(m.storeAgent.kbsync, global, dsid)
}

func (s *StoreAgent) initializeSession(globalContext uint32, dpInfo []byte) (uint64, error) {
	s.guest.beginCall()
	defer s.guest.clearScratch()

	dpInfoAddress, err := s.guest.scratch(dpInfo, uint64(len(dpInfo)))
	if err != nil {
		return 0, err
	}

	sessionField, err := s.guest.scratch(nil, 8)
	if err != nil {
		return 0, err
	}

	status, err := s.guest.invoke(
		storeAgentSessionInit,
		uint64(globalContext),
		dpInfoAddress,
		uint64(len(dpInfo)),
		sessionField,
	)
	if err != nil {
		return 0, fmt.Errorf("initialize StoreAgent session: %w", err)
	}

	if int32(status) != 0 {
		return 0, fmt.Errorf("StoreAgent session initialization returned %d", int32(status))
	}

	session, err := s.guest.readUint64(sessionField)
	if err != nil {
		return 0, err
	}

	if session == 0 {
		return 0, errors.New("StoreAgent session initialization returned a null session")
	}

	return session, nil
}

func (s *StoreAgent) Decrypt(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	if s == nil {
		return 0, errors.New("StoreAgent is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return 0, errors.New("StoreAgent is closed")
	}

	if ctx == nil {
		return 0, errors.New("StoreAgent decryption context is nil")
	}

	if dst == nil {
		return 0, errors.New("StoreAgent decryption destination is nil")
	}

	if src == nil {
		return 0, errors.New("StoreAgent decryption source is nil")
	}

	return decryptStream(ctx, dst, src, s.decryptChunk)
}

func (s *StoreAgent) decryptChunk(data []byte) error {
	s.guest.beginCall()
	defer s.guest.clearScratch()

	address, err := s.guest.scratch(data, uint64(len(data)))
	if err != nil {
		return err
	}

	status, err := s.guest.invoke(
		s.decryptEntry,
		s.session,
		address,
		uint64(len(data)),
		address,
		0,
	)
	if err != nil {
		return fmt.Errorf("decrypt StoreAgent chunk: %w", err)
	}

	if int32(status) != 0 {
		return fmt.Errorf("StoreAgent decryption returned %d", int32(status))
	}

	if err := s.guest.engine.MemReadInto(data, address); err != nil {
		return fmt.Errorf("read decrypted StoreAgent chunk: %w", err)
	}

	return nil
}

func decryptStream(ctx context.Context, dst io.Writer, src io.Reader, decrypt func([]byte) error) (int64, error) {
	buffer := make([]byte, storeAgentChunkSize)

	var written int64

	for {
		if err := ctx.Err(); err != nil {
			return written, fmt.Errorf("decrypt StoreAgent stream: %w", err)
		}

		count, readErr := io.ReadFull(src, buffer)
		if count != 0 {
			chunk := buffer[:count]
			if err := decrypt(chunk); err != nil {
				return written, err
			}

			n, err := dst.Write(chunk)
			written += int64(n)

			if err != nil {
				return written, fmt.Errorf("write decrypted StoreAgent stream: %w", err)
			}

			if n != len(chunk) {
				return written, fmt.Errorf("write decrypted StoreAgent stream: %w", io.ErrShortWrite)
			}
		}

		switch {
		case readErr == nil:
			continue
		case errors.Is(readErr, io.EOF), errors.Is(readErr, io.ErrUnexpectedEOF):
			return written, nil
		default:
			return written, fmt.Errorf("read encrypted StoreAgent stream: %w", readErr)
		}
	}
}

func (s *StoreAgent) Close() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	var errs []error

	if s.guest != nil && s.global != 0 {
		global := s.global
		s.global = 0
		s.session = 0

		status, err := s.guest.invoke(s.closeEntry, uint64(global))
		if err != nil {
			errs = append(errs, fmt.Errorf("close StoreAgent global context: %w", err))
		} else if int32(status) != 0 {
			errs = append(errs, fmt.Errorf("StoreAgent global context close returned %d", int32(status)))
		}
	}

	if s.guest != nil {
		errs = append(errs, s.guest.Close())
		s.guest = nil
	}

	return errors.Join(errs...)
}
