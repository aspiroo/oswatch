#include "../include/oswatch.h"
#include <sys/mman.h>    // ← ADD THIS LINE for MAP_FAILED

// Get syscall name from number
const char* get_syscall_name(long syscall_num) {
    switch (syscall_num) {
        // File operations
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 4: return "stat";
        case 5: return "fstat";
        case 6: return "lstat";
        case 7: return "poll";
        case 8: return "lseek";
        case 16: return "ioctl";
        case 17: return "pread64";
        case 18: return "pwrite64";
        case 19: return "readv";
        case 20: return "writev";
        case 21: return "access";
        case 22: return "pipe";
        case 32: return "dup";
        case 33: return "dup2";
        case 40: return "sendfile";
        case 72: return "fcntl";
        case 73: return "flock";
        case 74: return "fsync";
        case 75: return "fdatasync";
        case 76: return "truncate";
        case 77: return "ftruncate";
        case 78: return "getdents";
        case 79: return "getcwd";
        case 80: return "chdir";
        case 81: return "fchdir";
        case 82: return "rename";
        case 83: return "mkdir";
        case 84: return "rmdir";
        case 85: return "creat";
        case 86: return "link";
        case 87: return "unlink";
        case 88: return "symlink";
        case 89: return "readlink";
        case 90: return "chmod";
        case 91: return "fchmod";
        case 92: return "chown";
        case 93: return "fchown";
        case 217: return "getdents64";
        case 257: return "openat";
        case 258: return "mkdirat";
        case 259: return "mknodat";
        case 260: return "fchownat";
        case 261: return "futimesat";
        case 262: return "newfstatat";
        case 263: return "unlinkat";
        case 264: return "renameat";
        case 265: return "linkat";
        case 266: return "symlinkat";
        case 267: return "readlinkat";
        case 268: return "fchmodat";
        case 269: return "faccessat";
        
        // Memory management
        case 9: return "mmap";
        case 10: return "mprotect";
        case 11: return "munmap";
        case 12: return "brk";
        case 13: return "rt_sigaction";
        case 14: return "rt_sigprocmask";
        case 15: return "rt_sigreturn";
        case 25: return "mremap";
        case 26: return "msync";
        case 27: return "mincore";
        case 28: return "madvise";
        case 29: return "shmget";
        case 30: return "shmat";
        case 31: return "shmctl";
        
        // Process management
        case 24: return "sched_yield";
        case 34: return "pause";
        case 35: return "nanosleep";
        case 37: return "alarm";
        case 38: return "setitimer";
        case 39: return "getpid";
        case 41: return "socket";
        case 42: return "connect";
        case 43: return "accept";
        case 44: return "sendto";
        case 45: return "recvfrom";
        case 46: return "sendmsg";
        case 47: return "recvmsg";
        case 48: return "shutdown";
        case 49: return "bind";
        case 50: return "listen";
        case 51: return "getsockname";
        case 52: return "getpeername";
        case 53: return "socketpair";
        case 54: return "setsockopt";
        case 55: return "getsockopt";
        case 56: return "clone";
        case 57: return "fork";
        case 58: return "vfork";
        case 59: return "execve";
        case 60: return "exit";
        case 61: return "wait4";
        case 62: return "kill";
        case 63: return "uname";
        case 96: return "gettimeofday";
        case 97: return "getrlimit";
        case 98: return "getrusage";
        case 99: return "sysinfo";
        case 102: return "getuid";
        case 104: return "getgid";
        case 105: return "setuid";
        case 106: return "setgid";
        case 107: return "geteuid";
        case 108: return "getegid";
        case 110: return "getppid";
        case 111: return "getpgrp";
        case 112: return "setsid";
        case 186: return "gettid";
        case 202: return "futex";
        case 228: return "clock_gettime";
        case 230: return "clock_nanosleep";
        case 231: return "exit_group";
        case 232: return "epoll_wait";
        case 233: return "epoll_ctl";
        case 234: return "tgkill";
        case 281: return "epoll_pwait";
        case 318: return "getrandom";
        
        default: 
            return "unknown";
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

// Static variables for brk tracking (MUST be outside function or at top)
static void *initial_brk = NULL;
static void *last_brk = NULL;

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
                
                // Only track large allocations (likely libraries)
                if (size >= 65536) {  // 64 KB threshold
                    track_memory_allocation(stats, (void*)return_value, size, "mmap (library)");
                    
                    if (stats->verbose) {
                        printf("%s[MEMORY]%s mmap allocated %zu bytes at %p (library)\n",
                               COLOR_GREEN, COLOR_RESET, size, (void*)return_value);
                    }
                }
            }
            break;

        case 12:  // brk - Track heap size
            {
                void *new_brk = (void*)return_value;
                
                if (return_value == -1) break;
                
                if (initial_brk == NULL) {
                    initial_brk = new_brk;
                    last_brk = new_brk;
                    
                    if (stats->verbose) {
                        printf("%s[MEMORY]%s Initial heap at %p\n",
                            COLOR_CYAN, COLOR_RESET, new_brk);
                    }
                } else if (new_brk != last_brk) {
                    // Heap changed
                    if (new_brk > last_brk) {
                        size_t size = (char*)new_brk - (char*)last_brk;
                        
                        if (stats->verbose) {
                            printf("%s[MEMORY]%s Heap grew by %zu bytes (was %p, now %p)\n",
                                COLOR_GREEN, COLOR_RESET, size, last_brk, new_brk);
                        }
                        
                        // Track cumulative heap growth
                        stats->heap_allocated += size;
                    } else {
                        size_t size = (char*)last_brk - (char*)new_brk;
                        
                        if (stats->verbose) {
                            printf("%s[MEMORY]%s Heap shrunk by %zu bytes (was %p, now %p)\n",
                                COLOR_YELLOW, COLOR_RESET, size, last_brk, new_brk);
                        }
                        
                        stats->heap_freed += size;
                    }
                    
                    last_brk = new_brk;
                }
            }
            break;

        case 11:  // munmap
            if (return_value == 0) {
                // Memory was freed
                void *addr = (void*)regs->rdi;
                size_t size = regs->rsi;
                
                // Only track unmapping of large regions (libraries)
                // Small regions might be runtime management
                if (size >= 65536) {
                    track_memory_deallocation(stats, addr);
                    if (stats->verbose) {
                        printf("%s[MEMORY]%s munmap freed %zu bytes at %p (library)\n",
                               COLOR_YELLOW, COLOR_RESET, size, addr);
                    }
                } else {
                    // Small munmap - likely runtime, ignore
                    if (stats->verbose) {
                        printf("%s[MEMORY]%s munmap freed %zu bytes at %p (runtime, ignored)\n",
                               COLOR_CYAN, COLOR_RESET, size, addr);
                    }
                }
            }
            break;

        case 2:   // open
        case 257: // openat
            if (return_value >= 0) {
                stats->files_opened++;
                track_file_open(stats, return_value, NULL, regs->rsi);
                if (stats->verbose) {
                    printf("%s[FILE]%s Opened file descriptor:  %ld\n",
                           COLOR_MAGENTA, COLOR_RESET, return_value);
                }
            }
            break;

        case 3: // close
            if (return_value == 0) {
                stats->files_closed++;
                track_file_close(stats, regs->rdi);
                if (stats->verbose) {
                    printf("%s[FILE]%s Closed file descriptor\n",
                           COLOR_MAGENTA, COLOR_RESET);
                }
            }
            break;
    }
}
