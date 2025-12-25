#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("=== Comprehensive OSWatch Test ===\n");
    
    // Memory test
    int *data1 = malloc(1000);
    printf("Allocated 1000 bytes\n");
    
    int *data2 = malloc(500);
    free(data2);
    printf("Allocated and freed 500 bytes\n");
    
    // File test
    int fd = open("/tmp/oswatch_test.txt", O_CREAT | O_WRONLY, 0644);
    write(fd, "test", 4);
    close(fd);
    printf("File operations complete\n");
    
    // Intentional leak
    malloc(300);
    printf("Created intentional 300-byte leak\n");
    
    printf("=== Test Complete ===\n");
    return 0;
}