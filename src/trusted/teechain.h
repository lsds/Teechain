#ifndef _TEECHAIN_H_
#define _TEECHAIN_H_

#include "sgx_key_exchange.h"

// Temporary channel handle
#define TEMPORARY_CHANNEL_ID "0000011111111111111111111111111111111111111111111111111111100000"

// conversion and memory constants
#define MAX_ECALL_RETURN_SIZE 15000
#define MAX_INPUT_STR_LENGTH 500      // enclave arguments, such as the encoded redeem script, need to be shorter than this
#define MAX_NUM_STR_LENGTH 100
#define MAX_HEX_STR_LENGTH 1000

// bitcoin constants
#define BITCOIN_ADDRESS_LEN 34
#define BITCOIN_PUBLIC_KEY_LEN 66
#define BITCOIN_PRIVATE_KEY_LEN 52
#define BITCOIN_TX_HASH_LEN 64
#define BITCOIN_TX_SCRIPT_LEN 50

#define MAX_BITCOIN_TX_HEX_LEN 8192
#define MAX_BITCOIN_TX_SCRIPT_LEN 256

#define SATOSHI_PER_BITCOIN 100000000
#define MINER_TRANSACTION_FEE 10000 // in satoshi

#define MAX_AMOUNT_TO_RECEIVE_BEFORE_SYNC 0

#if defined(__cplusplus)
extern "C" {
#endif

bool check_and_decrypt_message(const char* blob, int blob_len, sgx_ra_context_t context, int msg_len, unsigned char* msg);
void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif /* !_TEECHAIN_H_ */
