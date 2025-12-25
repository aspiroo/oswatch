#ifndef OSWATCH_H
#define OSWATCH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

// ANSI Color codes for pretty output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

// Configuration
#define MAX_SYSCALL_NUM 400
#define HASH_TABLE_SIZE 256
#define MALLOC_HASH_SIZE 1024

// System call information structure
typedef struct {
    long syscall_number;
    const char *syscall_name;
    long args[6];              // System calls can have up to 6 arguments
    long return_value;
    double duration_ms;
    struct timespec timestamp;
} SyscallInfo;

// Memory block tracking structure (for mmap/brk tracking)
typedef struct MemoryBlock {
    void *address;
    size_t size;
    const char *syscall_type;  // "mmap", "brk", etc.
    struct timespec timestamp;
    struct MemoryBlock *next;
} MemoryBlock;

// Malloc block tracking structure (for malloc/free tracking from interceptor)
typedef struct MallocBlock {
    void *address;
    size_t size;
    struct MallocBlock *next;
} MallocBlock;

// File descriptor tracking structure
typedef struct FileDescriptor {
    int fd;
    char *filename;
    int flags;
    off_t bytes_read;
    off_t bytes_written;
    struct timespec opened_at;
    struct FileDescriptor *next;
} FileDescriptor;

// Overall process statistics
typedef struct {
    pid_t pid;
    char *process_name;

    // System call statistics
    size_t total_syscalls;
    size_t syscall_counts[MAX_SYSCALL_NUM];
    double total_syscall_time_ms;

    // Memory statistics (mmap/brk level)
    size_t total_memory_allocated;
    size_t total_memory_freed;
    size_t current_memory_usage;
    size_t peak_memory_usage;
    size_t double_free_count;
    MemoryBlock *memory_blocks;

    // Heap tracking (brk syscall level)
    size_t heap_allocated;
    size_t heap_freed;

    // Malloc tracking (from LD_PRELOAD interceptor)
    size_t malloc_allocations;
    size_t malloc_frees;
    size_t malloc_bytes_allocated;
    size_t malloc_bytes_freed;
    size_t malloc_bytes_leaked;
    MallocBlock *malloc_hash_table[MALLOC_HASH_SIZE];

    // File statistics
    int files_opened;
    int files_closed;
    FileDescriptor *open_files;

    // Timing
    struct timespec start_time;
    struct timespec end_time;
    double execution_time_ms;

    // Communication with malloc interceptor
    int notify_pipe[2];  // [0] = read, [1] = write

    // Flags
    int verbose;
    int program_started;
} ProcessStats;

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

// Process control (process_control.c)
int launch_and_monitor(char *program, char **args, ProcessStats *stats);
void monitor_process(pid_t pid, ProcessStats *stats);

// System call handling (syscall_handler.c)
void handle_syscall_entry(struct user_regs_struct *regs, ProcessStats *stats);
void handle_syscall_exit(struct user_regs_struct *regs, ProcessStats *stats, double duration);
const char* get_syscall_name(long syscall_num);

// File tracking (file_tracker.c)
void track_file_open(ProcessStats *stats, int fd, const char *name, int flags);
void track_file_close(ProcessStats *stats, int fd);

// Memory tracking - mmap/brk level (memory_tracker.c)
void track_memory_allocation(ProcessStats *stats, void *addr, size_t size, const char *type);
void track_memory_deallocation(ProcessStats *stats, void *addr);
void detect_memory_leaks(ProcessStats *stats);

// Malloc tracking - malloc/free level (malloc_tracker.c)
void process_malloc_events(ProcessStats *stats);
void detect_malloc_leaks(ProcessStats *stats);
void cleanup_malloc_table(ProcessStats *stats);

// Report generation (report.c)
void generate_report(ProcessStats *stats);
void print_statistics(ProcessStats *stats);

// Utility functions (main.c)
double calculate_time_diff(struct timespec *start, struct timespec *end);
void init_process_stats(ProcessStats *stats, pid_t pid, char *name);
void cleanup_process_stats(ProcessStats *stats);

#endif // OSWATCH_H