#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("Starting program with intentional memory leak...\n");
    
    // Allocate 1000 bytes
    int *data = malloc(1000);
    
    if (data == NULL) {
        printf("Memory allocation failed!\n");
        return 1;
    }
    
    printf("Allocated 1000 bytes at address: %p\n", data);
    
    // Intentionally NOT freeing the memory - this is the leak!
    // free(data);  // <-- This line is commented out
    
    printf("Program ending without freeing memory...\n");
    return 0;
}
