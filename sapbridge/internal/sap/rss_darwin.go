//go:build darwin

package sap

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
)

// MACH_TASK_BASIC_INFO is the correct flavor for arm64 iOS. The old
// TASK_BASIC_INFO (flavor 5) does not work on arm64 — the kernel
// returns garbage data. MACH_TASK_BASIC_INFO (flavor 20) always
// returns 64-bit fields and is the only correct flavor on iOS arm64.
const (
	machTaskBasicInfo      = 20  // MACH_TASK_BASIC_INFO
	machTaskBasicInfoCount = 12  // sizeof(mach_task_basic_info_data_t) / sizeof(natural_t) = 48/4
)

// mach_task_basic_info_data_t (mach/task_info.h):
//
//	struct mach_task_basic_info {
//	    mach_vm_size_t virtual_size;       // 8 bytes
//	    mach_vm_size_t resident_size;      // 8 bytes  ← what we want
//	    mach_vm_size_t resident_size_max;  // 8 bytes
//	    time_value_t   user_time;          // 8 bytes
//	    time_value_t   system_time;        // 8 bytes
//	    policy_t       policy;             // 4 bytes
//	    integer_t      suspend_count;      // 4 bytes
//	};
type machTaskBasicInfo struct {
	virtualSize       uint64
	residentSize      uint64 // ← the field we want
	residentSizeMax   uint64
	userTime          [2]int32 // time_value_t = {seconds, microseconds}
	systemTime        [2]int32
	policy            int32
	suspendCount      int32
}

// libSystem is the handle used to look up task_info / task_self_trap
// symbols. purego.Dlopen on iOS resolves the dyld shared cache.
var libSystem uintptr

func init() {
	handle, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err == nil {
		libSystem = handle
	}
}

// rssBytesProcFS is unused on Darwin (mach task_info covers it) but kept
// as a no-op so rss.go's call site compiles without platform-specific
// build tags.
func rssBytesProcFS() uint64 { return 0 }

// rssBytesMach returns the process's resident size in bytes via the
// mach task_info trap with MACH_TASK_BASIC_INFO flavor, or 0 on error.
func rssBytesMach() uint64 {
	if libSystem == 0 {
		return 0
	}

	// Resolve task_self_trap (iOS) or mach_task_self_ (macOS).
	var taskSelf func() uint32
	if handle, err := purego.Dlsym(libSystem, "task_self_trap"); err == nil && handle != 0 {
		purego.RegisterLibFunc(&taskSelf, libSystem, "task_self_trap")
	} else if handle, err := purego.Dlsym(libSystem, "mach_task_self_"); err == nil && handle != 0 {
		purego.RegisterLibFunc(&taskSelf, libSystem, "mach_task_self_")
	} else {
		return 0
	}

	var taskInfo func(uint32, uint32, unsafe.Pointer, *uint32) int32
	purego.RegisterLibFunc(&taskInfo, libSystem, "task_info")

	var info machTaskBasicInfo
	count := uint32(machTaskBasicInfoCount)
	task := taskSelf()
	kr := taskInfo(task, machTaskBasicInfo, unsafe.Pointer(&info), &count)
	if kr != 0 {
		fmt.Fprintf(os.Stderr, "[SAP] rss: task_info kr=%d\n", kr)
		return 0
	}

	return info.residentSize
}
