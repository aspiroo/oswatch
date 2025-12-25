#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("Mixed memory management test\n");
    
    // Good: allocated and freed
    int *good1 = malloc(200);
    printf("Allocated 200 bytes (will free)\n");
    free(good1);
    printf("Freed 200 bytes\n");
    
    // Bad: allocated but not freed
    char *bad1 = malloc(300);
    printf("Allocated 300 bytes (will NOT free - LEAK!)\n");
    
    // Good: allocated and freed
    double *good2 = malloc(400);
    printf("Allocated 400 bytes (will free)\n");
    free(good2);
    printf("Freed 400 bytes\n");
    
    // Bad: another leak
    int *bad2 = malloc(500);
    printf("Allocated 500 bytes (will NOT free - LEAK!)\n");
    
    printf("Ending: 2 leaks expected (300 + 500 bytes)\n");
    
    return 0;
}