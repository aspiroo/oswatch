# OSWatch - System Call Monitor & Memory Leak Detector

A production-grade debugging tool for Linux that combines **ptrace-based system call monitoring** with **LD_PRELOAD malloc interception** for precise memory leak detection.

---

## Features

### Memory Analysis
- **Accurate Malloc Leak Detection** - LD_PRELOAD-based interception of `malloc/calloc/realloc/free`
- **Individual Allocation Tracking** - Hash table with exact addresses and sizes
- **User vs Library Leak Classification** - Distinguishes user code from stdio/libc allocations
- **Heap Growth Monitoring** - `brk()` syscall-level tracking
- **Library Memory Mapping** - `mmap` allocation analysis

### Resource Tracking
- **File Descriptor Leak Detection** - Monitors `open/close` operations
- **File I/O Profiling** - Tracks read/write operations

### Performance Analysis
- **System Call Profiling** - Timing and frequency statistics
- **Execution Time Measurement** - Precise millisecond-level tracking
- **Syscall Duration Analysis** - Average and total time per syscall

### Output & Reporting
- **Color-Coded Reports** - Easy-to-read formatted output
- **Verbose Debugging Mode** - Real-time syscall and allocation logging
- **Statistical Summaries** - Comprehensive process statistics
- **Clear Verdicts** - "USER CODE IS LEAK-FREE" vs "USER CODE HAS LEAKS"
  
---

## Architecture

OSWatch uses a **two-component architecture**:

1. **OSWatch (Main)** - Ptrace-based process monitor
2. **liboswatch_malloc. so** - LD_PRELOAD malloc interceptor


### Key Technical Components: 
1. **Main Monitor** - Ptrace-based process tracer
2. **Malloc Interceptor** - LD_PRELOAD shared library
3. **Hash Table** - O(1) allocation lookup (1024 buckets)
4. **Pipe Communication** - Non-blocking inter-process messaging

---

## Installation

### Prerequisites
- **OS:** Linux (WSL)
- **Compiler:** GCC 7.0+
- **Tools:** Make
- **Kernel:** ptrace support enabled

### Build from Source

```bash
# Clone the repository
git clone https://github.com/aspiroo/oswatch.git
cd oswatch

# Build OSWatch and interceptor library
make

# Build test suite (optional)
make tests

# Basic Usage
./oswatch <program> [args...]

# Verbose Mode
./oswatch -v <program> [args...]

# Detect memory leaks:
./oswatch test/leak_test

# Monitor file operations:
./oswatch test/file_test

#Profile system calls:
./oswatch -v /bin/ls
