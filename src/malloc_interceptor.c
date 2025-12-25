#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

// Function pointers to real malloc/free/calloc/realloc
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void*) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;

static int initialized = 0;
static int notify_fd = -1;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

// Temporary buffer for bootstrap allocations
#define BOOTSTRAP_POOL_SIZE 1024 * 64
static char bootstrap_pool[BOOTSTRAP_POOL_SIZE];
static size_t bootstrap_offset = 0;

// Bootstrap malloc for use during initialization
static void* bootstrap_malloc(size_t size) {
    if (bootstrap_offset + size > BOOTSTRAP_POOL_SIZE) {
        return NULL;
    }
    void *ptr = &bootstrap_pool[bootstrap_offset];
    bootstrap_offset += size;
    return ptr;
}

static void init_interceptor() {
    if (initialized) return;
    
    pthread_mutex_lock(&init_mutex);
    if (initialized) {
        pthread_mutex_unlock(&init_mutex);
        return;
    }
    
    // Get real functions from libc
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    
    // Get notification pipe FD from environment
    char *fd_str = getenv("OSWATCH_NOTIFY_FD");
    if (fd_str) {
        notify_fd = atoi(fd_str);
    }
    
    initialized = 1;
    pthread_mutex_unlock(&init_mutex);
}

// Send notification to OSWatch
static void notify_oswatch(const char *msg) {
    if (notify_fd >= 0) {
        size_t len = strlen(msg);
        write(notify_fd, msg, len);
    }
}

// Intercept malloc
void* malloc(size_t size) {
    if (!initialized) {
        init_interceptor();
        if (!real_malloc) {
            return bootstrap_malloc(size);
        }
    }
    
    void *ptr = real_malloc(size);
    
    if (ptr && notify_fd >= 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "ALLOC %p %zu\n", ptr, size);
        notify_oswatch(buf);
    }
    
    return ptr;
}

// Intercept free
void free(void *ptr) {
    if (!initialized) {
        init_interceptor();
    }
    
    // Don't free bootstrap allocations
    if (ptr >= (void*)bootstrap_pool && 
        ptr < (void*)(bootstrap_pool + BOOTSTRAP_POOL_SIZE)) {
        return;
    }
    
    if (ptr && notify_fd >= 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "FREE %p\n", ptr);
        notify_oswatch(buf);
    }
    
    if (real_free) {
        real_free(ptr);
    }
}

// Intercept calloc
void* calloc(size_t nmemb, size_t size) {
    if (!initialized) {
        init_interceptor();
        if (!real_calloc) {
            // Bootstrap calloc
            void *ptr = bootstrap_malloc(nmemb * size);
            if (ptr) memset(ptr, 0, nmemb * size);
            return ptr;
        }
    }
    
    void *ptr = real_calloc(nmemb, size);
    
    if (ptr && notify_fd >= 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "ALLOC %p %zu\n", ptr, nmemb * size);
        notify_oswatch(buf);
    }
    
    return ptr;
}

// Intercept realloc
void* realloc(void *old_ptr, size_t size) {
    if (!initialized) {
        init_interceptor();
        if (!real_realloc) {
            // Bootstrap realloc
            void *new_ptr = bootstrap_malloc(size);
            return new_ptr;
        }
    }
    
    void *new_ptr = real_realloc(old_ptr, size);
    
    if (notify_fd >= 0) {
        if (old_ptr) {
            char buf[128];
            snprintf(buf, sizeof(buf), "FREE %p\n", old_ptr);
            notify_oswatch(buf);
        }
        if (new_ptr) {
            char buf[128];
            snprintf(buf, sizeof(buf), "ALLOC %p %zu\n", new_ptr, size);
            notify_oswatch(buf);
        }
    }
    
    return new_ptr;
}