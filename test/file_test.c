#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Testing file operations\n");
    
    // Create a file
    FILE *f1 = fopen("test_output.txt", "w");
    if (f1) {
        fprintf(f1, "Hello from OSWatch test!\n");
        fprintf(f1, "Testing file I/O operations.\n");
        fclose(f1);
        printf("File written and closed\n");
    }
    
    // Read it back
    FILE *f2 = fopen("test_output.txt", "r");
    if (f2) {
        char buffer[100];
        while (fgets(buffer, sizeof(buffer), f2)) {
            printf("Read: %s", buffer);
        }
        fclose(f2);
        printf("File read and closed\n");
    }
    
    return 0;
}