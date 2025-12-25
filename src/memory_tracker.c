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

            stats->total_memory_freed += to_remove->size;
            stats->current_memory_usage -= to_remove->size;

            free((char*)to_remove->syscall_type);
            free(to_remove);
            return;  // Found and freed
        }
        current = &(*current)->next;
    }
    
    if (stats->verbose) {
        // Silently ignore - this is expected for runtime unmaps    
        fprintf(stderr, "%s[ERROR]%s Double-free or invalid free detected at %p\n",
            COLOR_RED, COLOR_RESET, addr);
    }
    stats->double_free_count++;  
}

void detect_memory_leaks(ProcessStats *stats) {
    printf("\n%s╔═══════════════════════════════════════════════════════╗%s\n", 
           COLOR_RED, COLOR_RESET);
    printf("%s║           MEMORY LEAK ANALYSIS                        ║%s\n", 
           COLOR_RED, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n", 
           COLOR_RED, COLOR_RESET);
    
    int has_leaks = 0;
    
    // Check heap leaks
    size_t heap_leaked = stats->heap_allocated - stats->heap_freed;
    if (heap_leaked > 0) {
        has_leaks = 1;
        printf("%s⚠ HEAP MEMORY LEAK DETECTED:%s\n\n", COLOR_BOLD, COLOR_RESET);
        printf("  The program's heap grew but was never freed.\n");
        printf("  This includes malloc() calls and libc overhead.\n\n");
        printf("  Heap allocated: %s%zu bytes (%.2f KB)%s\n", 
               COLOR_YELLOW, stats->heap_allocated, stats->heap_allocated / 1024.0, COLOR_RESET);
        printf("  Heap freed:     %s%zu bytes (%.2f KB)%s\n", 
               COLOR_YELLOW, stats->heap_freed, stats->heap_freed / 1024.0, COLOR_RESET);
        printf("  %sNet leaked:      %zu bytes (%.2f KB)%s\n\n", 
               COLOR_RED, heap_leaked, heap_leaked / 1024.0, COLOR_RESET);
    }
    
    // Check mmap-based leaks
    if (stats->memory_blocks == NULL) {
        if (! has_leaks) {
            printf("%s✓ No memory leaks detected! %s\n", COLOR_GREEN, COLOR_RESET);
        }
    } else {
        // Count different types of leaks
        size_t malloc_leak_count = 0;
        size_t mmap_small_leak_count = 0;
        size_t large_leak_count = 0;
        size_t total_malloc_leaked = 0;
        size_t total_small_leaked = 0;
        size_t total_large_leaked = 0;
        
        // First pass: categorize leaks
        MemoryBlock *current = stats->memory_blocks;
        while (current) {
            if (strstr(current->syscall_type, "brk") != NULL || 
                strstr(current->syscall_type, "malloc") != NULL) {
                malloc_leak_count++;
                total_malloc_leaked += current->size;
            } else if (current->size < 65536) {
                mmap_small_leak_count++;
                total_small_leaked += current->size;
            } else {
                large_leak_count++;
                total_large_leaked += current->size;
            }
            current = current->next;
        }
        
        // Show runtime allocations (for information)
        if (mmap_small_leak_count > 0) {
            printf("%sℹ RUNTIME/STACK ALLOCATIONS (Not Bugs):%s\n", COLOR_CYAN, COLOR_RESET);
            printf("  These are C runtime and stack allocations.\n");
            printf("  They are managed automatically by the system.\n\n");
            
            printf("  Runtime allocations: %zu\n", mmap_small_leak_count);
            printf("  Total size:           %zu bytes (%.2f KB)\n\n", 
                   total_small_leaked, total_small_leaked / 1024.0);
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
    }
    
    // Overall summary
    printf("%s═══════════════════════════════════════════════════════%s\n", 
           COLOR_CYAN, COLOR_RESET);
    printf("%sTOTAL MEMORY SUMMARY:%s\n", COLOR_BOLD, COLOR_RESET);
    
    if (heap_leaked > 0) {
        printf("  %s⚠ HEAP LEAK:  %zu bytes not freed! %s\n",
               COLOR_RED, heap_leaked, COLOR_RESET);
        printf("  %sRecommendation: Check malloc/free pairs in your code. %s\n",
               COLOR_YELLOW, COLOR_RESET);
    } else {
        printf("  %s✓ Program memory management is correct!%s\n",
               COLOR_GREEN, COLOR_RESET);
    }
}