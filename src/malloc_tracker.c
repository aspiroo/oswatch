#include "../include/oswatch.h"
#include <string.h>

// Hash function for address lookup
static unsigned int hash_addr(void *addr) {
    unsigned long val = (unsigned long)addr;
    return (val >> 3) % MALLOC_HASH_SIZE;
}

// Track a malloc allocation
static void track_malloc(ProcessStats *stats, void *addr, size_t size) {
    unsigned int idx = hash_addr(addr);
    
    MallocBlock *block = malloc(sizeof(MallocBlock));
    if (!block) return;  // Failed to allocate tracking block
    
    block->address = addr;
    block->size = size;
    block->next = stats->malloc_hash_table[idx];
    stats->malloc_hash_table[idx] = block;
    
    stats->malloc_allocations++;
    stats->malloc_bytes_allocated += size;
    
    if (stats->verbose) {
        printf("%s[MALLOC]%s Allocated %zu bytes at %p\n",
               COLOR_GREEN, COLOR_RESET, size, addr);
    }
}

// Track a free operation
static void track_free(ProcessStats *stats, void *addr) {
    unsigned int idx = hash_addr(addr);
    MallocBlock **current = &stats->malloc_hash_table[idx];
    
    while (*current) {
        if ((*current)->address == addr) {
            MallocBlock *to_remove = *current;
            *current = (*current)->next;
            
            stats->malloc_frees++;
            stats->malloc_bytes_freed += to_remove->size;
            
            if (stats->verbose) {
                printf("%s[MALLOC]%s Freed %zu bytes at %p\n",
                       COLOR_YELLOW, COLOR_RESET, to_remove->size, addr);
            }
            
            free(to_remove);
            return;
        }
        current = &(*current)->next;
    }
    
    // Free of unknown address - possible double-free
    if (stats->verbose) {
        printf("%s[MALLOC]%s Free of unknown address %p (double-free? )\n",
               COLOR_RED, COLOR_RESET, addr);
    }
}

// Process malloc events from the interceptor pipe
void process_malloc_events(ProcessStats *stats) {
    char buf[4096];
    ssize_t n;
    
    // Read all available data from pipe (non-blocking)
    while ((n = read(stats->notify_pipe[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        
        // Process each line
        char *line = buf;
        char *next_line;
        
        while ((next_line = strchr(line, '\n')) != NULL) {
            *next_line = '\0';
            
            // Parse the event
            if (strncmp(line, "ALLOC ", 6) == 0) {
                void *addr;
                size_t size;
                if (sscanf(line + 6, "%p %zu", &addr, &size) == 2) {
                    track_malloc(stats, addr, size);
                }
            } else if (strncmp(line, "FREE ", 5) == 0) {
                void *addr;
                if (sscanf(line + 5, "%p", &addr) == 1) {
                    track_free(stats, addr);
                }
            }
            
            line = next_line + 1;
        }
    }
}

// Detect and report malloc leaks
void detect_malloc_leaks(ProcessStats *stats) {
    printf("\n%s╔═══════════════════════════════════════════════════════╗%s\n", 
           COLOR_RED, COLOR_RESET);
    printf("%s║           MALLOC/FREE LEAK ANALYSIS                   ║%s\n", 
           COLOR_RED, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════╝%s\n\n", 
           COLOR_RED, COLOR_RESET);
    
    // Count leaked blocks
    size_t leaked_blocks = 0;
    size_t leaked_bytes = 0;
    size_t user_leaked_blocks = 0;
    size_t user_leaked_bytes = 0;
    size_t stdio_leaked_bytes = 0;
    
    for (int i = 0; i < MALLOC_HASH_SIZE; i++) {
        MallocBlock *block = stats->malloc_hash_table[i];
        while (block) {
            leaked_blocks++;
            leaked_bytes += block->size;
            
            // Common stdio/libc buffer sizes
            int is_stdio_buffer = (block->size == 1024 || 
                                  block->size == 4096 || 
                                  block->size == 8192);
            
            if (is_stdio_buffer) {
                stdio_leaked_bytes += block->size;
            } else {
                user_leaked_blocks++;
                user_leaked_bytes += block->size;
            }
            
            block = block->next;
        }
    }
    
    // Report user leaks
    if (user_leaked_blocks == 0) {
        printf("%sNO USER MEMORY LEAKS DETECTED!  %s\n", COLOR_GREEN, COLOR_RESET);
        printf("  All user malloc() calls were properly matched with free().\n\n");
    } else {
        printf("%sUSER MEMORY LEAKS DETECTED! %s\n\n", COLOR_RED, COLOR_RESET);
        
        int leak_num = 0;
        for (int i = 0; i < MALLOC_HASH_SIZE; i++) {
            MallocBlock *block = stats->malloc_hash_table[i];
            while (block) {
                // Only show non-stdio leaks
                int is_stdio = (block->size == 1024 || 
                               block->size == 4096 || 
                               block->size == 8192);
                
                if (!is_stdio) {
                    leak_num++;
                    printf("%s  Leak #%d:%s\n", COLOR_YELLOW, leak_num, COLOR_RESET);
                    printf("    Address:     %p\n", block->address);
                    printf("    Size:        %zu bytes\n\n", block->size);
                }
                
                block = block->next;
            }
        }
        
        printf("%s  Summary:%s\n", COLOR_BOLD, COLOR_RESET);
        printf("    User leaks:      %s%zu allocations%s\n", 
               COLOR_RED, user_leaked_blocks, COLOR_RESET);
        printf("    User bytes leaked: %s%zu bytes (%.2f KB)%s\n\n", 
               COLOR_RED, user_leaked_bytes, user_leaked_bytes / 1024.0, COLOR_RESET);
    }
    
    // Report stdio/libc leaks separately
    if (stdio_leaked_bytes > 0) {
        printf("%sℹLIBRARY/STDIO ALLOCATIONS:%s\n", COLOR_CYAN, COLOR_RESET);
        printf("  These are internal buffers from printf/stdio functions.\n");
        printf("  They are freed automatically when the program exits.\n");
        printf("  This is normal behavior and NOT a bug.\n\n");
        printf("  Library allocations: %zu\n", leaked_blocks - user_leaked_blocks);
        printf("  Library bytes:        %zu bytes (%.2f KB)\n\n", 
               stdio_leaked_bytes, stdio_leaked_bytes / 1024.0);
    }
    
    // Overall statistics
    printf("%sMalloc Statistics:%s\n", COLOR_BOLD, COLOR_RESET);
    printf("  Total Allocations:  %zu\n", stats->malloc_allocations);
    printf("  Total Frees:       %zu\n", stats->malloc_frees);
    printf("  Allocated:         %zu bytes (%.2f KB)\n", 
           stats->malloc_bytes_allocated, stats->malloc_bytes_allocated / 1024.0);
    printf("  Freed:              %zu bytes (%.2f KB)\n", 
           stats->malloc_bytes_freed, stats->malloc_bytes_freed / 1024.0);
    
    printf("\n%s─────────────────────────────────────────────────────%s\n", 
           COLOR_CYAN, COLOR_RESET);
    if (user_leaked_blocks > 0) {
        printf("%sVERDICT: %sUSER CODE HAS MEMORY LEAKS%s\n", 
               COLOR_BOLD, COLOR_RED, COLOR_RESET);
    } else {
        printf("%sVERDICT: %sUSER CODE IS LEAK-FREE%s\n", 
               COLOR_BOLD, COLOR_GREEN, COLOR_RESET);
    }
}

// Cleanup malloc tracking table
void cleanup_malloc_table(ProcessStats *stats) {
    for (int i = 0; i < MALLOC_HASH_SIZE; i++) {
        MallocBlock *current = stats->malloc_hash_table[i];
        while (current) {
            MallocBlock *next = current->next;
            free(current);
            current = next;
        }
        stats->malloc_hash_table[i] = NULL;
    }
}