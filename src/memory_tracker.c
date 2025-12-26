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
           COLOR_CYAN, COLOR_RESET);
    printf("%s║           HEAP & LIBRARY MEMORY ANALYSIS              ║%s\n", 
           COLOR_CYAN, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n", 
           COLOR_CYAN, COLOR_RESET);
    
    // Heap tracking information (educational only)
    size_t heap_leaked = stats->heap_allocated - stats->heap_freed;
    
    if (heap_leaked > 0) {
        printf("%sℹHEAP SIZE TRACKING (brk syscall level):%s\n", COLOR_CYAN, COLOR_RESET);
        printf("  The program's heap was allocated but not returned to the OS.\n");
        printf("  This is NORMAL behavior - glibc does not shrink the heap after free().\n\n");
        
        printf("  Heap allocated:   %zu bytes (%.2f KB)\n", 
               stats->heap_allocated, stats->heap_allocated / 1024.0);
        printf("  Heap freed:      %zu bytes (%.2f KB)\n", 
               stats->heap_freed, stats->heap_freed / 1024.0);
        printf("  Heap size:       %zu bytes (%.2f KB)\n\n", 
               heap_leaked, heap_leaked / 1024.0);
        
        printf("  %sNote:%s For accurate leak detection, see MALLOC/FREE analysis above.\n\n",
               COLOR_BOLD, COLOR_RESET);
    }
    
    // Library allocations (mmap-based)
    if (stats->memory_blocks != NULL) {
        size_t large_leak_count = 0;
        size_t total_large_leaked = 0;
        
        MemoryBlock *current = stats->memory_blocks;
        while (current) {
            if (current->size >= 65536) {  // Libraries are typically > 64 KB
                large_leak_count++;
                total_large_leaked += current->size;
            }
            current = current->next;
        }
        
        if (large_leak_count > 0) {
            printf("%sℹ LIBRARY/SYSTEM ALLOCATIONS:%s\n", COLOR_CYAN, COLOR_RESET);
            printf("  These are shared libraries loaded by the system.\n");
            printf("  They remain in memory and are managed by the OS.\n");
            printf("  This is normal and NOT a memory leak.\n\n");
            
            printf("  Library allocations:  %zu\n", large_leak_count);
            printf("  Total size:           %zu bytes (%.2f MB)\n\n", 
                   total_large_leaked, total_large_leaked / (1024.0 * 1024.0));
        }
    }
}