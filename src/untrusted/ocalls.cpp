#include <time.h>

#include "ocalls.h"
#include "utils.h"

// prints the given message
void ocall_print(const char* msg) {
    print_important(msg);
}

void ocall_error(const char* msg) {
    error(msg);
}

// prints the message as important
void ocall_print_important(const char* msg) {
    print_important(msg);
}

// ocall sleeps for 100 milliseconds
void ocall_monotonic_counter_sleep() {
    struct timespec tim, tim2;
    tim.tv_sec = 0;
    tim.tv_nsec = 1000 * 1000 * 100 ; // 100 milliseconds

    // Increment Counter
    log_debug("%s", "Sleeping for 100 milliseconds");

    if (nanosleep(&tim , &tim2) < 0 ) {
        error("Nano sleep system call failed \n");
    }
}
