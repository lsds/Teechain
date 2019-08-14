#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "channel.h"
#include "state.h"

// encrypted message constants
#define ADD_DEPOSIT 1
#define REMOVE_DEPOSIT 2
#define ADD_DEPOSIT_ACK 3
#define REMOVE_DEPOSIT_ACK 4

#define BACKUP_STORE_ACK 5
#define REMOVE_BACKUP 6
#define BACKUP_REMOVE_ACK 7

#define CHANNEL_UPDATE_ACK 8

// ecall return constants to notify untrusted how to react
#define SEND_SECURE_ACK 100
#define SEND_INSECURE_ACK 101
#define SEND_LOCAL_ACK 102
#define SEND_BITCOIN_PAYMENT 103
#define SEND_BACKUP_STORE_REQUEST 104
#define SEND_CHANNEL_CREATE_ACK 105
#define SEND_DEPOSIT_ADD_REQUEST 106
#define SEND_DEPOSIT_ADD_ACK 107
#define SEND_DEPOSIT_REMOVE_REQUEST 108
#define SEND_DEPOSIT_REMOVE_ACK 109
#define SEND_UPDATE_CHANNEL_BALANCE_REQUEST 111
#define SEND_UPDATE_CHANNEL_BALANCE_ACK 112

#define REQUEST_FAILED 113  // don't kill the enclave
#define REQUEST_CRASHED 114 // kill the enclave -- failure is really bad!

// encryption and authentication constants
#define ID_BYTE_LEN 50
#define IV_BYTE_LEN 16
#define AES_BYTE_LEN 32
#define AES_BITS (AES_BYTE_LEN*8)
#define NONCE_BYTE_LEN 16

// teechain constants
#define CHANNEL_ID_LEN 16
#define MAX_NUM_SETUP_DEPOSITS 10
#define MAX_NUM_DEPOSITS_IN_CHANNEL 10
#define MAX_NUM_CHANNELS_IN_CHAIN 10
#define MAX_NUM_CHANNELS_PER_ENCLAVE 10

struct CreateChannelMsg {
    char channel_id[CHANNEL_ID_LEN];
    char bitcoin_address[BITCOIN_ADDRESS_LEN];
    unsigned long long num_deposits;

    char txids[MAX_NUM_SETUP_DEPOSITS * BITCOIN_TX_HASH_LEN];
    unsigned long long tx_indexes[MAX_NUM_SETUP_DEPOSITS];
    unsigned long long deposit_amounts[MAX_NUM_SETUP_DEPOSITS];

    unsigned long long deposit_script_lengths[MAX_NUM_SETUP_DEPOSITS];
    char deposit_scripts[MAX_NUM_SETUP_DEPOSITS * MAX_BITCOIN_TX_SCRIPT_LEN];

    char deposit_bitcoin_addresses[MAX_NUM_SETUP_DEPOSITS * BITCOIN_ADDRESS_LEN];
    char deposit_public_keys[MAX_NUM_SETUP_DEPOSITS * BITCOIN_PUBLIC_KEY_LEN];
    char deposit_private_keys[MAX_NUM_SETUP_DEPOSITS * BITCOIN_PRIVATE_KEY_LEN];

    char padding[8]; // pad message to multiple of 16 bytes for encryption/decryption
};

struct DepositMsg {
    char deposit_operation;
    char nonce[NONCE_BYTE_LEN];
    char channel_id[CHANNEL_ID_LEN];
    unsigned long long deposit_id;
    char padding[7]; // pad message to multiple of 16 bytes for encryption/decryption
};

struct SecureAckMsg {
    char channel_id[CHANNEL_ID_LEN];
    char nonce[NONCE_BYTE_LEN];
    char result;
    char padding[15]; // pad message to multiple of 16 bytes for encryption/decryption
};

struct BackupStoredAckMsg {
    char channel_id[CHANNEL_ID_LEN];
    char blocked_channel_id[CHANNEL_ID_LEN];
    char nonce[NONCE_BYTE_LEN];
    char result;
    bool any_failures;  // were there any failures on the way?
    char padding[13]; // pad message to multiple of 16 bytes for encryption/decryption
};

struct SendMsg {
    unsigned long long monotoniccount;
    unsigned long long amount;
};

struct DepositStateMsg {
    bool is_remote_deposit;
    char txid[BITCOIN_TX_HASH_LEN];
    unsigned long long tx_index;
    unsigned long long deposit_amount;

    unsigned long long deposit_script_length;
    char deposit_script[MAX_BITCOIN_TX_SCRIPT_LEN];

    char public_key[BITCOIN_PUBLIC_KEY_LEN];
    char bitcoin_address[BITCOIN_ADDRESS_LEN];

    unsigned long long deposit_id; // used only back backup states
};

struct ChannelStateMsg {
    char channel_id[CHANNEL_ID_LEN];
    unsigned long long balance_a;
    unsigned long long balance_b;
    char bitcoin_address_a[BITCOIN_ADDRESS_LEN];
    char bitcoin_address_b[BITCOIN_ADDRESS_LEN];

    unsigned long long num_deposits;
    struct DepositStateMsg deposit_states[MAX_NUM_DEPOSITS_IN_CHANNEL];
};

struct BackupDepositStateMsg {
    struct DepositStateMsg deposit_state;
    char private_key[BITCOIN_PRIVATE_KEY_LEN];
};

struct BackupSetupTransactionStateMsg {
    char my_address[BITCOIN_ADDRESS_LEN];
    unsigned long long miner_fee;
    unsigned long long num_deposits;
    struct BackupDepositStateMsg deposit_states[MAX_NUM_SETUP_DEPOSITS];
};

struct BackupChannelStateMsg {
    char channel_id[CHANNEL_ID_LEN];
    unsigned long long balance_a;
    unsigned long long balance_b;
    char bitcoin_address_a[BITCOIN_ADDRESS_LEN];
    char bitcoin_address_b[BITCOIN_ADDRESS_LEN];

    unsigned long long num_deposits;
    struct BackupDepositStateMsg deposit_states[MAX_NUM_DEPOSITS_IN_CHANNEL];
};

struct BackupRequest {
    BackupBlockRequest request_blocked_on; // why did this channel need to backup?
    unsigned long long send_amount_blocked_on; // if backup request is for send_amount, what is it?
    unsigned long long deposit_id_blocked_on; // if backup request is for deposit add/remove, what is it?
    char nonce[NONCE_BYTE_LEN]; // nonce for this request
};

struct BackupEnclaveStateMsg {
    char backup_channel_id[CHANNEL_ID_LEN];  // the channel id of the backup channel 
    char blocked_channel_id[CHANNEL_ID_LEN]; // the channel id that was blocked waiting for backup

    struct BackupRequest blocked_request;  // the backup request blocked on
    bool any_failures;  // any_failures along the backup path

    struct BackupSetupTransactionStateMsg my_setup_transaction;

    unsigned long long num_channels;
    struct BackupChannelStateMsg channel_states[MAX_NUM_CHANNELS_PER_ENCLAVE];

    char padding[6]; // pad message to multiple of 16 bytes for encryption/decryption
};

struct RemoveBackupMsg {
    char backup_channel_id[CHANNEL_ID_LEN];
    char nonce[NONCE_BYTE_LEN];
    char request;
    char padding[15]; // pad message to multiple of 16 bytes for encryption/decryption
};

// Update message used for sends and receives
struct UpdateChannelBalanceMsg {
    char backup_channel_id[CHANNEL_ID_LEN];
    char blocked_channel_id[CHANNEL_ID_LEN];
    bool any_failures;

    unsigned long long my_balance;
    unsigned long long remote_balance;
    char my_bitcoin_address[BITCOIN_ADDRESS_LEN];
    char remote_bitcoin_address[BITCOIN_ADDRESS_LEN];

    char nonce[NONCE_BYTE_LEN];
    char padding[6]; // pad message to multiple of 16 bytes for encryption/decryption
};

#endif /* !_NETWORK_H_ */
