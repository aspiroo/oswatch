#include "../include/oswatch.h"

// Get syscall name from number (simplified version)
const char* get_syscall_name(long syscall_num) {
    // This is a simplified mapping for common syscalls
    // Full list would have 400+ entries
    switch (syscall_num) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 9: return "mmap";
        case 11: return "munmap";
        case 12: return "brk";
        case 21: return "access";
        case 57: return "fork";
        case 59: return "execve";
        case 60: return "exit";
        case 257: return "openat";
        case 262: return "newfstatat";
        default: return "unknown";
    }
}

void handle_syscall_entry(struct user_regs_struct *regs, ProcessStats *stats) {
    // On x86_64:
    // - syscall number is in orig_rax
    // - arguments are in: rdi, rsi, rdx, r10, r8, r9

    long syscall_num = regs->orig_rax;

    // Bounds check
    if (syscall_num < 0 || syscall_num >= MAX_SYSCALL_NUM) {
        return;
    }

    // Update statistics
    stats->total_syscalls++;
    stats->syscall_counts[syscall_num]++;

    // Get syscall name
    const char *syscall_name = get_syscall_name(syscall_num);

    // Verbose output
    if (stats->verbose) {
        printf("%s[SYSCALL]%s %-15s (num=%ld, args: 0x%llx, 0x%llx, 0x%llx)\n",
               COLOR_BLUE, COLOR_RESET,
               syscall_name,
               syscall_num,
               regs->rdi, regs->rsi, regs->rdx);
    }
}

void handle_syscall_exit(struct user_regs_struct *regs, ProcessStats *stats, double duration) {
    long syscall_num = regs->orig_rax;
    long return_value = regs->rax;  // Return value is in rax

    stats->total_syscall_time_ms += duration;

    // Handle specific syscalls based on their behavior
    switch (syscall_num) {
        case 9:  // mmap
            if (return_value > 0 && return_value != -1) {
                // Memory was allocated
                size_t size = regs->rsi;  // Second argument is size
                track_memory_allocation(stats, (void*)return_value, size, "mmap");

                if (stats->verbose) {
                    printf("%s[MEMORY]%s mmap allocated %zu bytes at %p\n",
                           COLOR_GREEN, COLOR_RESET, size, (void*)return_value);
                }
            }
            break;

        case 12: // brk
            // Track heap changes
            if (stats->verbose && return_value != -1) {
                printf("%s[MEMORY]%s brk changed heap to %p\n",
                       COLOR_GREEN, COLOR_RESET, (void*)return_value);
            }
            break;

        case 11: // munmap
            if (return_value == 0) {
                // Memory was freed
                void *addr = (void*)regs->rdi;
                track_memory_deallocation(stats, addr);
                if (stats->verbose) {
                    printf("%s[MEMORY]%s munmap freed memory at %p\n",
                           COLOR_YELLOW, COLOR_RESET, addr);
                }
            }
            break;

        case 2:   // open
        case 257: // openat
            if (return_value >= 0) {
                stats->files_opened++;
                if (stats->verbose) {
                    printf("%s[FILE]%s Opened file descriptor: %ld\n",
                           COLOR_MAGENTA, COLOR_RESET, return_value);
                }
            }
            break;

        case 3: // close
            if (return_value == 0) {
                stats->files_closed++;
                if (stats->verbose) {
                    printf("%s[FILE]%s Closed file descriptor\n",
                           COLOR_MAGENTA, COLOR_RESET);
                }
            }
            break;
    }
}
