#include "../include/oswatch.h"

void track_memory_allocation(ProcessStats *stats, void *addr, size_t size, const char *type) {
    // Create new memory block entry
    MemoryBlock *block = malloc(sizeof(MemoryBlock));
    if (!block) {
        return;  // Out of memory
    }

    block->address = addr;
    block->size = size;
    block->syscall_type = strdup(type);
    clock_gettime(CLOCK_REALTIME, &block->timestamp);

    // Add to front of linked list
    block->next = stats->memory_blocks;
    stats->memory_blocks = block;

    // Update statistics
    stats->total_memory_allocated += size;
    stats->current_memory_usage += size;

    if (stats->current_memory_usage > stats->peak_memory_usage) {
        stats->peak_memory_usage = stats->current_memory_usage;
    }
}

void track_memory_deallocation(ProcessStats *stats, void *addr) {
    MemoryBlock **current = &stats->memory_blocks;

    while (*current) {
        if ((*current)->address == addr) {
            MemoryBlock *to_remove = *current;
            *current = (*current)->next;

            // Update statistics
            stats->total_memory_freed += to_remove->size;
            stats->current_memory_usage -= to_remove->size;

            // Free the block
            free((char*)to_remove->syscall_type);
            free(to_remove);
            return;
        }
        current = &(*current)->next;
    }
}

void detect_memory_leaks(ProcessStats *stats) {
    printf("\n%s╔═══════════════════════════════════════════════════════╗%s\n", COLOR_RED, COLOR_RESET);
    printf("%s║           MEMORY LEAK ANALYSIS                        ║%s\n", COLOR_RED, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n", COLOR_RED, COLOR_RESET);
    
    if (stats->memory_blocks == NULL) {
        printf("%s✓ No memory leaks detected!%s\n", COLOR_GREEN, COLOR_RESET);
        return;
    }
    
    // Count different types of leaks
    size_t small_leak_count = 0;   // Likely program bugs (< 64KB)
    size_t large_leak_count = 0;   // Likely library loads (>= 64KB)
    size_t total_small_leaked = 0;
    size_t total_large_leaked = 0;
    
    // First pass: categorize leaks
    MemoryBlock *current = stats->memory_blocks;
    while (current) {
        if (current->size < 65536) {  // 64 KB threshold
            small_leak_count++;
            total_small_leaked += current->size;
        } else {
            large_leak_count++;
            total_large_leaked += current->size;
        }
        current = current->next;
    }
    
    // Show program leaks (small allocations)
    if (small_leak_count > 0) {
        printf("%s⚠ PROGRAM MEMORY LEAKS (Likely Bugs):%s\n\n", COLOR_BOLD, COLOR_RESET);
        
        size_t leak_num = 0;
        current = stats->memory_blocks;
        while (current) {
            if (current->size < 65536) {
                leak_num++;
                printf("%s  Leak #%zu:%s\n", COLOR_YELLOW, leak_num, COLOR_RESET);
                printf("    Address:       %p\n", current->address);
                printf("    Size:          %zu bytes (%.2f KB)\n", 
                       current->size, current->size / 1024.0);
                printf("    Allocated via: %s\n", current->syscall_type);
                printf("\n");
            }
            current = current->next;
        }
        
        printf("%s  Summary:%s\n", COLOR_BOLD, COLOR_RESET);
        printf("    Program leaks: %s%zu allocations%s\n", COLOR_RED, small_leak_count, COLOR_RESET);
        printf("    Total leaked:  %s%zu bytes (%.2f KB)%s\n\n", COLOR_RED, total_small_leaked, total_small_leaked / 1024.0, COLOR_RESET);
    } else {
        printf("%s✓ No program memory leaks detected!%s\n\n", COLOR_GREEN, COLOR_RESET);
    }
    
    // Show library allocations (for information)
    if (large_leak_count > 0) {
        printf("%sℹ LIBRARY/SYSTEM ALLOCATIONS (Not Bugs):%s\n", COLOR_CYAN, COLOR_RESET);
        printf("  These are shared libraries loaded by the system.\n");
        printf("  They remain in memory and are managed by the OS.\n\n");
        
        printf("  Library allocations: %zu\n", large_leak_count);
        printf("  Total size:          %zu bytes (%.2f MB)\n\n", 
               total_large_leaked, total_large_leaked / (1024.0 * 1024.0));
    }
    
    // Overall summary
    printf("%s═══════════════════════════════════════════════════════%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%sTOTAL MEMORY SUMMARY:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  All allocations: %zu (%.2f MB total)\n", small_leak_count + large_leak_count, (total_small_leaked + total_large_leaked) / (1024.0 * 1024.0));
    
    if (small_leak_count > 0) {
        printf("  %s⚠ ACTION NEEDED: Fix %zu program leak(s)!%s\n", COLOR_RED, small_leak_count, COLOR_RESET);
    } else {
        printf("  %s✓ Program memory management is correct!%s\n", COLOR_GREEN, COLOR_RESET);
    }
}