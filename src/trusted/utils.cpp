#include <cstdlib>
#include <cerrno>
#include <climits>
#include <stdexcept>
#include <stdarg.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <stdexcept>
#include <ctype.h>

#include <univalue.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <random.h>

#include "rpc.h"
#include "teechain.h"
#include "teechain_t.h"
#include "utils.h"

extern bool debug;

std::string buffer_to_hex(unsigned char *buf, int len) {
    char hex_str[MAX_HEX_STR_LENGTH];
    char* hex_ptr = hex_str;

    if (len*2 > MAX_HEX_STR_LENGTH) {
	return std::string("buffer too big to serialize");
    }

    for (unsigned char *ptr = buf; ptr < (buf+len); ++ptr) {
        hex_ptr += snprintf(hex_ptr, MAX_HEX_STR_LENGTH - 1 - (hex_ptr - hex_str), "%02x", *ptr);
    }
    *(hex_ptr + 1) = '\0';

    return std::string(hex_str);
}

// input: a null-terminated ASCII string with only alphanumeric characters
// output: a C++ string or NULL if error
std::string sanitize_string_from_buffer(const char *input) {
  if (strlen(input) > MAX_INPUT_STR_LENGTH) {
    return NULL;
  }
  for (const char *strp = input; *strp; ++strp) {
    if (!isalnum(*strp)) {
      return NULL;
    }
  }
  std::string instr(input);
  return instr;
}

// input: a null-terminated ASCII string containing a hexadecimal value
// output: a C++ string or NULL if error
std::string sanitize_hexstring_from_buffer(const char *input) {
  for (const char *strp = input; *strp; ++strp) {
    if (!isxdigit(*strp)) {
      return NULL;
    }
  }
  std::string instr(input);
  return instr;
}

void dump_buffer(unsigned char *buf, int len) {
    printf("Buffer of %d bytes", len);
    for (int i=0; i < len;) {
      if (i + 7 < len) {
        printf("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x ", buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
	i += 8;
      } else {
        printf("0x%02x", buf[i]);
	++i;
      }
    }
}

std::string long_long_to_string(unsigned long long num) {
    char buffer[MAX_NUM_STR_LENGTH];
    snprintf(buffer, MAX_NUM_STR_LENGTH, "%llu", num);
    return std::string(buffer);
}

unsigned long long string_to_long_long(std::string str) {
    return (strtoull(str.c_str(), NULL, 10));
}

std::string remove_surrounding_quotes(std::string str) {
    return str.substr(1, str.size() - 2);
}

std::string satoshi_to_bitcoin(unsigned long long amount) {
    unsigned long long satoshi_in_bitcoin = SATOSHI_PER_BITCOIN;

    unsigned long long bitcoin = amount / SATOSHI_PER_BITCOIN;
    unsigned long long satoshi = amount % SATOSHI_PER_BITCOIN;

    char btc_str[MAX_NUM_STR_LENGTH];
    snprintf(btc_str, MAX_NUM_STR_LENGTH, "%llu.%08llu", bitcoin, satoshi);
    return std::string(btc_str);
}

void log_debug(const char *fmt, ...) {
    if (debug) {
        char buf[BUFSIZ+1] = {'\0'};
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, BUFSIZ, fmt, ap);
        va_end(ap);
        ocall_print(buf);
    }
}

void printf(const char *fmt, ...) {
    char buf[BUFSIZ+1] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

void print_important(const char *fmt, ...)
{
    char buf[BUFSIZ+1] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_important(buf);
}

// generate a random nonce string for message freshness
std::string generate_random_nonce() {
    char nonce_bytes[NONCE_BYTE_LEN];
    GetRandBytes((unsigned char*) nonce_bytes, NONCE_BYTE_LEN);
    return std::string(nonce_bytes, NONCE_BYTE_LEN);
}
