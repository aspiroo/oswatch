#include "../include/oswatch.h"

void track_file_open(ProcessStats *stats, int fd, const char *name, int flags) {

    FileDescriptor *f = malloc(sizeof(FileDescriptor));
    f->fd = fd;
    f->flags = flags;
    f->bytes_read = 0;
    f->bytes_written = 0;
    f->filename = name ? strdup(name) : strdup("<unknown>");
    clock_gettime(CLOCK_MONOTONIC, &f->opened_at);

    f->next = stats->open_files;
    stats->open_files = f;
}

void track_file_close(ProcessStats *stats, int fd) {

    FileDescriptor *prev = NULL, *cur = stats->open_files;

    while (cur) {
        if (cur->fd == fd) {
            if (prev) prev->next = cur->next;
            else stats->open_files = cur->next;

            free(cur->filename);
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
}
