#include "teechain.h"
#include "utils.h"
#include "channel.h"

extern int debug;
extern int error_count;

// for debugging -- dumps a buffer to stdout
void dump_buffer(unsigned char *buf, int len) {
    printf("\nBuffer of %d bytes", len);
    for (int i=0; i < len;) {
        printf("0x%02x", buf[i]);
        ++i;
    }
    printf("\n");
}

// for console output and debugging
void output_message_and_time(std::string msg, int code) {
    std::string reset_code = "\033[0m";

    time_t _tm = time(NULL);
    struct tm *currtime = localtime(&_tm);
    char* time = asctime(currtime);
    time[strlen(time) - 1] = '\0';

    //std::cout << "[" << time << "] " << "\033[" << code << "m" << msg << reset_code << std::endl;
    std::cout << "[" << time << "] " << msg << std::endl;
}

// print the given information in bold
void print_important(std::string msg) {
    output_message_and_time(msg, BOLD);
}

// print to out
void print(std::string msg) {
    output_message_and_time(msg, DEFAULT_COLOUR);
}

// print to error and exit
void error(std::string msg) {
    error_count += 1;

    if (error_count == 1) {  // Only print first error
        std::cerr << "Error something went wrong: " << msg << std::endl;
        std::cerr << "To prevent fund loss, we are shutting down your enclave, returning your unused deposits, and terminating all your channels. Check your log for the transactions." << std::endl;

        char user_output[MAX_ECALL_RETURN_LENGTH];
        shutdown_enclave(user_output);
        std::cerr << std::string(user_output) << std::endl;
    }
 
    cleanup();
    exit(1);
}

// print log for debugging
void log_debug(const char *fmt, ...) {
    if (debug) {
        char buf[BUFSIZ] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        output_message_and_time(buf, DEFAULT_COLOUR);
    }
}
