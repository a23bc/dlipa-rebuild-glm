import Darwin

/// Resident size of this process in MiB.
///
/// The account-switch probe needs a number that moves when the store runtime is
/// closed and opened again: timings say whether a reopen is cheap, and this says
/// whether the session that closed left anything behind. `task_info` is public
/// Mach API, so this costs nothing to carry in a shipping build.
enum ProcessMemory {
    /// -1 when the kernel refuses, so "no answer" cannot be read as a small
    /// process. Nothing depends on the value being right to the megabyte; it is
    /// the slope across three switches that the probe is looking at.
    static func residentMiB() -> Int {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), rebound, &count)
            }
        }

        guard result == KERN_SUCCESS else { return -1 }

        return Int(info.resident_size / (1024 * 1024))
    }
}
