CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
LDFLAGS =

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj

# Executable name
TARGET = oswatch

# Source files (list them explicitly)
SRCS = src/main.c \
       src/process_control.c \
       src/syscall_handler.c \
       src/memory_tracker.c \
       src/report.c

# Object files
OBJS = obj/main.o \
       obj/process_control.o \
       obj/syscall_handler.o \
       obj/memory_tracker.o \
       obj/report.o

# Default target
all: $(TARGET)

# Create obj directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Link object files to create executable
$(TARGET): $(OBJ_DIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)
	@echo ""
	@echo "=========================================="
	@echo "Build complete!"
	@echo "Run with: ./oswatch ./test/leak_test"
	@echo "=========================================="

# Compile each source file
obj/main.o: src/main.c include/oswatch.h
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/main.c -o obj/main.o

obj/process_control.o: src/process_control.c include/oswatch.h
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/process_control.c -o obj/process_control.o

obj/syscall_handler.o: src/syscall_handler.c include/oswatch.h
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/syscall_handler.c -o obj/syscall_handler.o

obj/memory_tracker.o: src/memory_tracker.c include/oswatch.h
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/memory_tracker.c -o obj/memory_tracker.o

obj/report.o: src/report.c include/oswatch.h
	mkdir -p obj
	$(CC) $(CFLAGS) -c src/report.c -o obj/report.o

# Clean build files
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Clean complete!"

# Phony targets
.PHONY: all clean