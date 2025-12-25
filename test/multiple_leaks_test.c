#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("Program with multiple memory leaks\n");
    
    // Leak 1
    int *data1 = malloc(100);
    printf("Allocated 100 bytes\n");
    
    // Leak 2
    char *data2 = malloc(500);
    printf("Allocated 500 bytes\n");
    
    // Leak 3
    double *data3 = malloc(1000);
    printf("Allocated 1000 bytes\n");
    
    // None freed intentionally!
    printf("Ending without freeing memory...\n");
    
    return 0;
}