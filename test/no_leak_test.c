#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("This is a well-behaved program!\n");
    
    // Allocate memory
    int *data = malloc(500);
    
    if (data == NULL) {
        printf("Allocation failed!\n");
        return 1;
    }
    
    printf("Allocated 500 bytes\n");
    
    // Use the memory
    for (int i = 0; i < 100; i++) {
        data[i] = i;
    }
    
    // FREE THE MEMORY (good practice!)
    free(data);
    printf("Memory properly freed!\n");
    
    return 0;
}