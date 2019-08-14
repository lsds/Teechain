#ifndef _UTILS_H_
#define _UTILS_H_

#include <string>

#include "channel.h"

#define TOSTR(x)  long_long_to_string(x)

std::string buffer_to_hex(unsigned char *buf, int len);

std::string sanitize_string_from_buffer(const char *input);
std::string sanitize_hexstring_from_buffer(const char *input);

void dump_buffer(unsigned char *buf, int len);

std::string long_long_to_string(unsigned long long num);
unsigned long long string_to_long_long(std::string str);

std::string remove_surrounding_quotes(std::string str);
std::string satoshi_to_bitcoin(unsigned long long satoshi);

void print_my_bitcoin_information(ChannelState *s);
void print_remote_bitcoin_information(ChannelState *s);
void print_security_information(ChannelState *s);
void print_setup_and_refund_information(ChannelState *s);
void print_balance_and_counter_information(ChannelState *s);

void log_debug(const char *fmt, ...);
void print(const char *fmt, ...);
void print_important(const char *fmt, ...);

std::string generate_random_nonce();

#endif
