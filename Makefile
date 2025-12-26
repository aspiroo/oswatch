CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS =

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

# Executable name
TARGET = oswatch

# Malloc interceptor shared library
INTERCEPTOR = liboswatch_malloc.so

# Source files
SRCS = src/main.c \
       src/process_control.c \
       src/syscall_handler.c \
       src/memory_tracker.c \
       src/file_tracker.c \
       src/malloc_tracker.c \
       src/report.c

# Object files
OBJS = obj/main.o \
       obj/process_control.o \
       obj/syscall_handler.o \
       obj/memory_tracker.o \
       obj/file_tracker.o \
       obj/malloc_tracker.o \
       obj/report.o

# Default target - build both oswatch and interceptor
all: $(TARGET) $(INTERCEPTOR)

# Create obj directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Link object files to create executable
$(TARGET): $(OBJ_DIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)
	@echo ""
	@echo "=========================================="
	@echo "Build complete!"
	@echo "Run with: ./oswatch test/leak_test"
	@echo "=========================================="

# Build the malloc interceptor shared library
$(INTERCEPTOR): src/malloc_interceptor.c
	$(CC) -shared -fPIC -o $(INTERCEPTOR) src/malloc_interceptor.c -ldl -lpthread
	@echo "Built malloc interceptor:  $(INTERCEPTOR)"

# Compile each source file
obj/main.o: src/main.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/main.c -o obj/main.o

obj/process_control.o: src/process_control.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/process_control.c -o obj/process_control.o

obj/syscall_handler.o: src/syscall_handler.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/syscall_handler.c -o obj/syscall_handler.o

obj/memory_tracker.o: src/memory_tracker.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/memory_tracker.c -o obj/memory_tracker.o

obj/file_tracker.o: src/file_tracker.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/file_tracker.c -o obj/file_tracker.o

obj/malloc_tracker.o: src/malloc_tracker.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/malloc_tracker.c -o obj/malloc_tracker.o

obj/report.o: src/report.c include/oswatch.h
	@mkdir -p obj
	$(CC) $(CFLAGS) -c src/report.c -o obj/report.o

# Build test programs
tests: test/leak_test test/no_leak_test test/multiple_leaks_test test/mixed_test test/file_test test/comprehensive_test

test/leak_test: test/leak_test.c
	$(CC) -o test/leak_test test/leak_test.c

test/no_leak_test:  test/no_leak_test.c
	$(CC) -o test/no_leak_test test/no_leak_test.c

test/multiple_leaks:  test/multiple_leaks_test.c
	$(CC) -o test/multiple_leaks test/multiple_leaks_test.c

test/mixed_test: test/mixed_test.c
	$(CC) -o test/mixed_test test/mixed_test.c

test/file_test: test/file_test.c
	$(CC) -o test/file_test test/file_test.c

test/comprehensive_test: test/comprehensive_test.c
	$(CC) -o test/comprehensive_test test/comprehensive_test.c

# Clean build files
clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(INTERCEPTOR)
	rm -f test/leak_test test/no_leak_test test/multiple_leaks test/mixed_test test/file_test
	@echo "Clean complete!"

# Phony targets
.PHONY:  all clean tests