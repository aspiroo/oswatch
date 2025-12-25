#include "../include/oswatch.h"
#include <fcntl.h>

int launch_and_monitor(char *program, char **args, ProcessStats *stats) {
    // Create pipe for malloc interceptor communication
    if (pipe(stats->notify_pipe) == -1) {
        perror("pipe failed");
        return -1;
    }
    
    // Make read end non-blocking
    int flags = fcntl(stats->notify_pipe[0], F_GETFL, 0);
    fcntl(stats->notify_pipe[0], F_SETFL, flags | O_NONBLOCK);
    
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (child_pid == 0) {
        // CHILD PROCESS

        // Close read end of pipe
        close(stats->notify_pipe[0]);
        
        // Set environment variable for interceptor
        char fd_str[32];
        snprintf(fd_str, sizeof(fd_str), "%d", stats->notify_pipe[1]);
        setenv("OSWATCH_NOTIFY_FD", fd_str, 1);
        
        // Set LD_PRELOAD to load our interceptor
        setenv("LD_PRELOAD", "./liboswatch_malloc.so", 1);

        // Allow parent to trace this process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace TRACEME failed");
            exit(1);
        }

        // Execute target program
        execvp(program, args);

        // If execvp returns, it failed
        perror("execvp failed");
        exit(1);
        
    } else {
        // PARENT PROCESS

        // Close write end of pipe
        close(stats->notify_pipe[1]);
        
        stats->pid = child_pid;

        // Wait for child to stop after PTRACE_TRACEME
        int status;
        waitpid(child_pid, &status, 0);

        // Set ptrace options
        if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, 
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
            perror("ptrace SETOPTIONS failed");
            return -1;
        }

        // Start monitoring
        monitor_process(child_pid, stats);

        // Process any remaining malloc events
        process_malloc_events(stats);
        
        // Close pipe
        close(stats->notify_pipe[0]);

        // Record end time
        clock_gettime(CLOCK_MONOTONIC, &stats->end_time);
        stats->execution_time_ms = calculate_time_diff(&stats->start_time, &stats->end_time);
    }
    return 0;
}

void monitor_process(pid_t pid, ProcessStats *stats) {
    int status;
    int in_syscall = 0;
    struct user_regs_struct regs;
    struct timespec syscall_start, syscall_end;
    
    while (1) {
        // Process malloc events from interceptor
        process_malloc_events(stats);
        
        // Continue execution until next syscall
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            break;
        }
        
        // Wait for child to stop
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid failed");
            break;
        }
        
        // Check if process exited
        if (WIFEXITED(status)) {
            if (stats->verbose) {
                printf("%s[PROCESS]%s Exited with code %d\n", 
                       COLOR_YELLOW, COLOR_RESET, WEXITSTATUS(status));
            }
            break;
        }
        
        // Check if process was terminated by signal
        if (WIFSIGNALED(status)) {
            if (stats->verbose) {
                printf("%s[PROCESS]%s Terminated by signal %d\n", 
                       COLOR_RED, COLOR_RESET, WTERMSIG(status));
            }
            break;
        }
        
        // Check if stopped by syscall
        if (WIFSTOPPED(status)) {
            int stop_signal = WSTOPSIG(status);
            
            if (stop_signal != SIGTRAP && stop_signal != (SIGTRAP | 0x80)) {
                ptrace(PTRACE_SYSCALL, pid, 0, stop_signal);
                continue;
            }
            
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                break;
            }
        }
        
        // Get register values
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            break;
        }
        
        if (! in_syscall) {
            clock_gettime(CLOCK_MONOTONIC, &syscall_start);
            handle_syscall_entry(&regs, stats);
            in_syscall = 1;
        } else {
            clock_gettime(CLOCK_MONOTONIC, &syscall_end);
            double duration = calculate_time_diff(&syscall_start, &syscall_end);
            handle_syscall_exit(&regs, stats, duration);
            in_syscall = 0;
        }
    }
}