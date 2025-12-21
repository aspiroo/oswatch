#include "../include/oswatch.h"

void print_statistics(ProcessStats *stats) {
    printf("%s╔═══════════════════════════════════════════════════════╗%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s║               PROCESS STATISTICS                      ║%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n", COLOR_CYAN, COLOR_RESET);

    // Process info
    printf("%sProcess Information:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  PID:            %d\n", stats->pid);
    printf("  Name:           %s\n", stats->process_name);
    printf("  Execution Time: %.2f ms\n\n", stats->execution_time_ms);

    // System call stats
    printf("%sSystem Call Statistics:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  Total Syscalls: %zu\n", stats->total_syscalls);
    printf("  Total Time:     %.2f ms\n", stats->total_syscall_time_ms);
    if (stats->total_syscalls > 0) {
        printf("  Avg Duration:   %.4f ms\n", stats->total_syscall_time_ms / stats->total_syscalls);
    }
    printf("\n");

    // Memory stats
    printf("%sMemory Statistics:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  Total Allocated: %zu bytes (%.2f KB)\n", stats->total_memory_allocated,stats->total_memory_allocated / 1024.0);
    printf("  Total Freed:     %zu bytes (%.2f KB)\n", stats->total_memory_freed,stats->total_memory_freed / 1024.0);
    printf("  Peak Usage:      %zu bytes (%.2f KB)\n", stats->peak_memory_usage,stats->peak_memory_usage / 1024.0);
    printf("  Current Usage:   %zu bytes (%.2f KB)\n", stats->current_memory_usage,stats->current_memory_usage / 1024.0);
    printf("\n");

    // File stats
    printf("%sFile Operations:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  Files Opened:  %d\n", stats->files_opened);
    printf("  Files Closed:  %d\n", stats->files_closed);

    if (stats->files_opened != stats->files_closed) {
        printf("  %s Warning: %d file(s) not properly closed!%s\n",
               COLOR_YELLOW,
               stats->files_opened - stats->files_closed,
               COLOR_RESET);
    } else {
        printf("  %s✓ All files properly closed%s\n", COLOR_GREEN, COLOR_RESET);
    }
}

void generate_report(ProcessStats *stats) {
    print_statistics(stats);
    detect_memory_leaks(stats);
    printf("\n%s═══════════════════════════════════════════════════════%s\n",  COLOR_CYAN, COLOR_RESET);
    printf("%sAnalysis complete!%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s═══════════════════════════════════════════════════════%s\n\n", COLOR_CYAN, COLOR_RESET);
}
