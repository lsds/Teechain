#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>
#include <iostream>
#include <stdio.h>
#include <cstring>
#include <cstdarg>

#include <sgx_urts.h>
#include "service_provider.h"
#include "sgx_ukey_exchange.h"

// colour constants for std::out
#define RED 31
#define GREEN 32
#define BLUE 44
#define BOLD 1
#define UNDERLINE 4
#define DEFAULT_COLOUR 39
#define RESET 0

// useful macros
#define streq(s1,s2)    (strncmp((s1),(s2),strlen(s2)) == 0)

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

// functions for printing to log, stdout and error
void log_debug(const char *fmt, ...);
void dump_buffer(unsigned char *buf, int len); // useful for debugging

void print(std::string msg);
void print_important(std::string msg);

void error(std::string msg);

#endif /* !_UTILS_H_ */
