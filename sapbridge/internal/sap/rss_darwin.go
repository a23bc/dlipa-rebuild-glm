//go:build darwin

package sap

import (
        "fmt"
        "os"
        "unsafe"

        "github.com/ebitengine/purego"
)

// mach task_info constants (mach/task_info.h). On 64-bit Darwin the
// flavor we want is TASK_BASIC_INFO_64 (= 5) and the matching count
// is TASK_BASIC_INFO_64_COUNT (= 8 natural_t = 32 bytes).
//
// Named with a Flavor suffix so the constant doesn't collide with
// the taskBasicInfo struct type below.
const (
        taskBasicInfoFlavor      = 5 // TASK_BASIC_INFO_64 flavor
        taskBasicInfoFlavorCount = 8 // sizeof(task_basic_info_64_data_t)/sizeof(natural_t)
)

// taskBasicInfo mirrors task_basic_info_64_data_t (mach/task_info.h).
//
//      struct task_basic_info_64_data_t {
//          integer_t       suspend_count;  // 4 bytes
//          mach_vm_size_t  virtual_size;   // 8 bytes
//          mach_vm_size_t  resident_size;  // 8 bytes  ← what we want
//          time_value_t    user_time;      // 8 bytes
//          time_value_t    system_time;    // 8 bytes
//          policy_t        policy;         // 4 bytes
//      };
type taskBasicInfo struct {
        suspendCount int32
        virtualSize  uint64
        residentSize uint64
        userTime     [2]int32 // time_value_t = {seconds, microseconds}
        systemTime   [2]int32
        policy       int32
}

// libSystem is the handle used to look up task_info / task_self_trap
// symbols at package init time. purego.Dlopen on iOS also resolves
// the dyld shared cache. If the lookup fails, libSystem is 0 and
// rssBytesMach returns 0 (caller falls back to /proc or skips).
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
// mach task_info trap, or 0 if anything goes wrong (caller falls back
// to /proc or skips reporting).
func rssBytesMach() uint64 {
        if libSystem == 0 {
                return 0
        }

        // Resolve task_self_trap (iOS) or mach_task_self_ (macOS) for the
        // current task port. Both return mach_port_t (uint32 on Darwin).
        var taskSelf func() uint32
        if handle, err := purego.Dlsym(libSystem, "task_self_trap"); err == nil && handle != 0 {
                purego.RegisterLibFunc(&taskSelf, libSystem, "task_self_trap")
        } else if handle, err := purego.Dlsym(libSystem, "mach_task_self_"); err == nil && handle != 0 {
                purego.RegisterLibFunc(&taskSelf, libSystem, "mach_task_self_")
        } else {
                return 0
        }

        // task_info(task_t target_task,
        //           task_flavor_t flavor,
        //           task_info_t task_info_out,         // void *
        //           mach_msg_type_number_t *task_info_count);
        var taskInfo func(uint32, uint32, unsafe.Pointer, *uint32) int32
        purego.RegisterLibFunc(&taskInfo, libSystem, "task_info")

        var info taskBasicInfo
        count := uint32(taskBasicInfoFlavorCount)
        task := taskSelf()
        kr := taskInfo(task, taskBasicInfoFlavor, unsafe.Pointer(&info), &count)
        if kr != 0 {
                fmt.Fprintf(os.Stderr, "[SAP] rss: task_info kr=%d\n", kr)
                return 0
        }

        return info.residentSize
}

