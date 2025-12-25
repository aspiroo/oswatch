#include "../include/oswatch.h"

void print_banner() {
    printf("\n");
    printf("%s╔═══════════════════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║              OSWATCH - System Call Monitor            ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║          Process & Memory Analysis Tool               ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n", COLOR_CYAN, COLOR_RESET);
    printf("\n");
}

void print_usage(char *program_name) {
    printf("Usage: %s [OPTIONS] <program> [program_args...]\n\n", program_name);
    printf("Options:\n");
    printf("  -v, --verbose     Show detailed system call information\n");
    printf("  -h, --help        Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s ./leak_test\n", program_name);
    printf("  %s -v ./leak_test\n", program_name);
    printf("  %s /bin/ls -la\n\n", program_name);
}

int main(int argc, char *argv[]) {
    // Check minimum arguments
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse command line options
    int verbose = 0;
    int program_index = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            program_index++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            break;  // Found program name
        }
    }

    // Check if program name was provided
    if (program_index >= argc) {
        fprintf(stderr, "%sError: No program specified%s\n", COLOR_RED, COLOR_RESET);
        print_usage(argv[0]);
        return 1;
    }

    char *target_program = argv[program_index];

    // Print banner
    print_banner();

    printf("%sTarget Program:%s %s\n", COLOR_BOLD, COLOR_RESET, target_program);
    if (verbose) {
        printf("%sMode:%s Verbose\n", COLOR_BOLD, COLOR_RESET);
    }
    printf("\n");
    printf("%s═══════════════════════════════════════════════════════%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%sStarting monitoring...%s\n\n", COLOR_GREEN, COLOR_RESET);

    // Initialize statistics
    ProcessStats stats;
    init_process_stats(&stats, 0, target_program);
    stats.verbose = verbose;

    // Launch and monitor the target program
    int result = launch_and_monitor(target_program, &argv[program_index], &stats);

    if (result != 0) {
        fprintf(stderr, "%sError: Failed to monitor process%s\n", COLOR_RED, COLOR_RESET);
        cleanup_process_stats(&stats);
        return 1;
    }

    // Generate final report
    printf("\n%s═══════════════════════════════════════════════════════%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%sMonitoring complete. Generating report...%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s═══════════════════════════════════════════════════════%s\n\n", COLOR_CYAN, COLOR_RESET);

    generate_report(&stats);

    // Cleanup
    cleanup_process_stats(&stats);

    return 0;
}

// Initialize process statistics structure
void init_process_stats(ProcessStats *stats, pid_t pid, char *name) {
    memset(stats, 0, sizeof(ProcessStats));
    
    stats->pid = pid;
    stats->process_name = name;
    stats->memory_blocks = NULL;
    stats->open_files = NULL;
    
    // Record start time
    clock_gettime(CLOCK_MONOTONIC, &stats->start_time);
}

// Cleanup and free allocated memory
void cleanup_process_stats(ProcessStats *stats) {
    // Cleanup memory blocks
    MemoryBlock *mem_current = stats->memory_blocks;
    while (mem_current) {
        MemoryBlock *next = mem_current->next;
        free((char*)mem_current->syscall_type);
        free(mem_current);
        mem_current = next;
    }
    
    // Cleanup file descriptors
    FileDescriptor *file_current = stats->open_files;
    while (file_current) {
        FileDescriptor *next = file_current->next;
        free(file_current->filename);
        free(file_current);
        file_current = next;
    }
    
    // Cleanup malloc hash table
    cleanup_malloc_table(stats);
}

// Calculate time difference in milliseconds
double calculate_time_diff(struct timespec *start, struct timespec *end) {
    double start_ms = start->tv_sec * 1000.0 + start->tv_nsec / 1000000.0;
    double end_ms = end->tv_sec * 1000.0 + end->tv_nsec / 1000000.0;
    return end_ms - start_ms;
}
