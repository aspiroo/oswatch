#include "../include/oswatch.h"

int launch_and_monitor(char *program, char **args, ProcessStats *stats) {
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("fork failed");
        return -1;
    }

    if (child_pid == 0) {
        // CHILD PROCESS: This will become the target program

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
        // PARENT PROCESS: This is OSWatch - the monitor

        stats->pid = child_pid;

        // Wait for child to stop after PTRACE_TRACEME
        int status;
        waitpid(child_pid, &status, 0);

        // Set ptrace options
        ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);

        // Start monitoring
        monitor_process(child_pid, stats);

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
        // Continue execution until next syscall
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            perror("ptrace SYSCALL failed");
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
        
        // Get register values
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            perror("ptrace GETREGS failed");
            break;
        }
        
        if (!in_syscall) {
            // ENTERING system call
            clock_gettime(CLOCK_MONOTONIC, &syscall_start);
            handle_syscall_entry(&regs, stats);
            in_syscall = 1;
        } else {
            // EXITING system call
            clock_gettime(CLOCK_MONOTONIC, &syscall_end);
            double duration = calculate_time_diff(&syscall_start, &syscall_end);
            handle_syscall_exit(&regs, stats, duration);
            in_syscall = 0;
        }
    }
}