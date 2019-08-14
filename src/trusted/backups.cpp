#include <string>

#include "backups.h"
#include "channel.h"
#include "network.h"
#include "teechain.h"
#include "utils.h"

extern bool benchmark;

extern TeechanState teechain_state;
extern SetupTransaction my_setup_transaction;

// Function declarations to avoid circular dependencies
bool check_message_nonce(ChannelState* channel, char* message_nonce);
struct BackupEnclaveStateMsg generate_backup_message_for_storage(std::string nonce);
struct BackupEnclaveStateMsg generate_backup_message(std::string backup_channel_id, std::string blocked_channel_id, struct BackupRequest, bool any_failures);
int send_secure_update_channel_ack(std::string given_channel_id, std::string blocked_channel_id, std::string given_nonce, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_bitcoin_payment_message(std::string given_channel_id, unsigned long long amount, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_receive_ack(std::string given_channel_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_channel_create_ack(std::string given_channel_id, char* next_channel_id_to_send_on, int* send_action);

int send_add_deposit_request(std::string channel_id_s, unsigned long long deposit_index, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_remove_deposit_request(std::string channel_id_s, unsigned long long deposit_index, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);

int send_remove_deposit_ack(std::string channel_id_s, std::string given_nonce, unsigned long long deposit_index, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_add_deposit_ack(std::string channel_id_s, std::string given_nonce, unsigned long long deposit_index, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);

int send_local_ack(std::string given_channel_id, char* next_channel_id_to_send_on, int* send_action);
std::vector<unsigned long long> find_deposit_ids_in_channel(std::string channel_id, std::map<unsigned long long, std::string> deposit_ids_to_channels);
int sgx_encrypt(ChannelState *state, unsigned char *plain, int plainlen, unsigned char *cypher, sgx_aes_gcm_128bit_tag_t *p_out_mac);
int sgx_decrypt(unsigned char *cypher, int cypherlen, unsigned char *p_gcm_mac, sgx_ra_context_t context, unsigned char *plain);
std::string generate_random_nonce();
std::map<unsigned long long, Deposit> extract_deposit_mapping_from_backup();
void update_backup_channels(bool is_initiator, std::string channel_id);

// Global backup state
// Saved first state?
bool saved_first_backup_state;
// Backup to secure storage?
bool write_to_stable_storage = false;

// Backup using backup enclaves?
std::string prev_backup_channel_id = "";
std::string next_backup_channel_id = "";

// Backed up data stored
// TODO: make this more robust, so we can handle out of order back up requests
struct BackupEnclaveStateMsg most_recent_backup_state;
struct UpdateChannelBalanceMsg most_recent_channel_update_state;

bool have_backup() {
    return prev_backup_channel_id.length() != 0;
}

static bool have_existing_backup_state() {
    return saved_first_backup_state;
}

// increments a monotonic counter and writes state to stable storage
void increment_monotonic_counter_and_write_state_to_storage(std::string channel_id) {
    struct BackupEnclaveStateMsg msg = generate_backup_message_for_storage(generate_random_nonce());
    uint32_t in_len = sizeof(struct BackupEnclaveStateMsg);
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];
    ChannelState* state = get_channel_state(channel_id);

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
    }

    // Sleep for time to increment counter
    ocall_monotonic_counter_sleep();
}

int send_backup_store_request(std::string blocked_channel_id, struct BackupRequest blocked_request, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) { 
    //printf("Sending backup store request: %s, %s", prev_backup_channel_id.c_str(), blocked_channel_id.c_str()); 
 
    // send update message to backup and wait for response 
    struct BackupEnclaveStateMsg msg = generate_backup_message(prev_backup_channel_id, blocked_channel_id, blocked_request, any_failures); 
    uint32_t in_len = sizeof(struct BackupEnclaveStateMsg); 
 
    // encrypt message 
    unsigned char outbuf[in_len]; 
    unsigned char outmac[SAMPLE_SP_TAG_SIZE]; 
 
    ChannelState* backup_state = get_channel_state(prev_backup_channel_id); 
    if (sgx_encrypt(backup_state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) { 
        printf("encryption failed, should never happen, shutting down"); 
        return 1; 
    } 
 
    // copy out to untrusted memory 
    memcpy(encrypted_data_out, outbuf, in_len); 
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE); 
    *encrypted_data_out_len = in_len; 
    std::memcpy(next_channel_id_to_send_on, prev_backup_channel_id.c_str(), CHANNEL_ID_LEN); 
    *send_action = SEND_BACKUP_STORE_REQUEST; 
 
    return 0; 
} 

int send_update_channel_balance_request(std::string blocked_channel_id, std::string nonce, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    // create update channel balance message 
    struct UpdateChannelBalanceMsg msg;
    uint32_t in_len = sizeof(struct UpdateChannelBalanceMsg);

    //log_debug("send_update_channel_balance_request: %s, %s", prev_backup_channel_id.c_str(), blocked_channel_id.c_str());

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    
    if (check_state(Funded)) {
        //log_debug("Primary filling message!");
        //log_debug("Backup channel id: %s", prev_backup_channel_id.c_str());
        // fill message with my state and send
        ChannelState* blocked_state = get_channel_state(blocked_channel_id);
    
        memcpy(msg.backup_channel_id, prev_backup_channel_id.c_str(), CHANNEL_ID_LEN);
        memcpy(msg.blocked_channel_id, blocked_channel_id.c_str(), CHANNEL_ID_LEN);
    
        msg.my_balance = blocked_state->my_balance;
        msg.remote_balance = blocked_state->remote_balance;
        memcpy(msg.my_bitcoin_address, my_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
        memcpy(msg.remote_bitcoin_address, blocked_state->remote_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
        memcpy(msg.nonce, nonce.c_str(), NONCE_BYTE_LEN);
        msg.any_failures = false;
    } else if (teechain_state == Backup) {
        msg = most_recent_channel_update_state;
        msg.any_failures = any_failures;
        memcpy(msg.backup_channel_id, prev_backup_channel_id.c_str(), CHANNEL_ID_LEN); // update with our backup channel
    }

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];
 
    if (sgx_encrypt(backup_state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return 1;
    }
    
    // copy out to untrusted memory
    memcpy(encrypted_data_out, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    std::memcpy(next_channel_id_to_send_on, prev_backup_channel_id.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_UPDATE_CHANNEL_BALANCE_REQUEST;

    return 0;
}

static int send_secure_backup_ack(std::string given_channel_id, std::string blocked_channel_id, std::string given_nonce, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(given_channel_id);

    //log_debug("Sending secure backup ack: %s, %s", given_channel_id.c_str(), blocked_channel_id.c_str());

    // construct secure ack
    struct BackupStoredAckMsg ack;
    uint32_t in_len = sizeof(struct BackupStoredAckMsg);

    // fill message
    memcpy(ack.channel_id, given_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.blocked_channel_id, blocked_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.nonce, given_nonce.c_str(), NONCE_BYTE_LEN);
    ack.result = BACKUP_STORE_ACK;
    ack.any_failures = any_failures;

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &ack, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return 1;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data_out, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    memcpy(next_channel_id_to_send_on, given_channel_id.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_SECURE_ACK;

    return 0;
}

int ecall_create_new_backup_channel(const char *channel_id, int channel_len, bool is_initiator) {
    std::string channel_id_s(channel_id, channel_len);

    if (!check_state(Funded) && !check_state(Backup)) {
        printf("Cannot create new backup channel; this enclave is not funded!");
        return 1;
    }

    if (write_to_stable_storage) {
        printf("Cannot create a backup channel! We are using stable storage for fault tolerance!");
        return 1;
    }

    if (is_initiator && check_state(Funded)) {
        printf("Only backup nodes can initiate when a new backup node is being added to the chain!");
        return 1;
    }

    if (is_initiator) {
        // check not already backup for someone else
        if (next_backup_channel_id.length() != 0) {
            printf("I'm already a backup node for someone else!");
            return 1;
        }
    } else {
        // check no backup already exists
        if (prev_backup_channel_id.length() != 0) {
            printf("A backup node already exists! Unable to add another backup for this node!");
            return 1;
        }
    }


    // create channel state
    ChannelState* state = create_channel_state();
    state->is_initiator = is_initiator;
    state->is_backup_channel = true; // the purpose of this channel is to be a backup only
    associate_channel_state(channel_id_s, state);

    update_backup_channels(is_initiator, channel_id_s);

    return 0;
}

int ecall_backup() {
    if (!check_state(Ghost)) {
        printf("Cannot assign this node as backup; not in the correct state!");
        return 1;
    }
    teechain_state = Backup;
    return 0;
}

int ecall_verify_backup_removed(const char *data, int data_len, sgx_ra_context_t context) {
    // TODO: state check

    struct SecureAckMsg msg;
    if (!check_and_decrypt_message(data, data_len, context, sizeof(struct SecureAckMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    ChannelState* state = get_channel_state(channel_id);

    if (channel_id != prev_backup_channel_id) {
        printf("Cannot accept this backup ack! It is not from my backup!!");
        printf("Given channel: %s, Expected channel: %s", channel_id.c_str(), prev_backup_channel_id.c_str());
        return 1;
    }

    // check secure ack and nonce
    if (!check_message_nonce(state, msg.nonce)) {
        return 1;
    }

    if (msg.result != BACKUP_REMOVE_ACK) {
        printf("ecall_verify_backup_removed: invalid ack response");
        return 1;
    }

    return 0;
}

int ecall_verify_channel_update_stored(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char *next_channel_id_to_send_on, int* send_action) {

    struct BackupStoredAckMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct BackupStoredAckMsg), (unsigned char*) &msg)) {
        REQUEST_CRASHED; // decryption failed
    }

    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    std::string blocked_channel_id(msg.blocked_channel_id, CHANNEL_ID_LEN);
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    bool any_failures = msg.any_failures;
    ChannelState* state = get_channel_state(channel_id.c_str());

    if (channel_id != prev_backup_channel_id) {
        printf("Received an ack from someone other than our backup!");
        any_failures = any_failures || true;
    }

    // Get request we expect
    std::map<std::string, BackupRequest>::iterator it = state->backup_requests.find(given_nonce);
    if (it == state->backup_requests.end()) {
        printf("Error! We didn't find the in-flight request!!");
        any_failures = any_failures || true;
    }

    struct BackupRequest backup_request = state->backup_requests[given_nonce];
    std::string backup_request_nonce(backup_request.nonce, NONCE_BYTE_LEN);

    // check secure ack and nonce
    if (msg.result != CHANNEL_UPDATE_ACK) {
        printf("ecall_verify_channel_update_stored: invalid ack response");
        any_failures = any_failures || true;
    }

    if (given_nonce != backup_request_nonce) {
        printf("The given ack nonce doesn't match the oldest backup request nonce!");
        printf("Given: %s, Expected: %s", given_nonce.c_str(), backup_request_nonce.c_str());
        any_failures = any_failures || true;
    }


    if (teechain_state == Backup) { // send secure ack to next node in the chain
        if (!benchmark) {
            printf("We have just received an ack for the channel update! Send ack to the next node in the chain!");
        }
        ChannelState* next_state = get_channel_state(next_backup_channel_id);
        return send_secure_update_channel_ack(next_backup_channel_id, blocked_channel_id, given_nonce, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    // We are the primary

    if (any_failures) {
        printf("We received a failure somewhere along the backup path!");
        return REQUEST_FAILED;

    } else if (backup_request.request_blocked_on == Send_Bitcoin_Request) {
        if (!benchmark) {
            printf("Send bitcoin payment! We are the primary and we got an ack from our backup!");
        }
        return send_bitcoin_payment_message(blocked_channel_id, backup_request.send_amount_blocked_on, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Receive_Bitcoin_Request) {
        if (!benchmark) {
            printf("Send insecure payment ack! We are the primary and we just received an ack from our backup!");
        }
        ChannelState* blocked_state = get_channel_state(blocked_channel_id);
        blocked_state->unsynced_bitcoin_amount -= backup_request.send_amount_blocked_on;
        return send_receive_ack(blocked_channel_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    printf("Unable to find request to ack!");
    return REQUEST_CRASHED; // invalid message type
}

int ecall_verify_backup_stored(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char *next_hop_channel_id, bool* routing_complete, char *next_channel_id_to_send_on, int* send_action) {
    struct BackupStoredAckMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct BackupStoredAckMsg), (unsigned char*) &msg)) {
        return REQUEST_CRASHED; // decryption failed
    }

    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    std::string blocked_channel_id(msg.blocked_channel_id, CHANNEL_ID_LEN);
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    bool any_failures = msg.any_failures;

    //log_debug("Verifying backup stored: %s, %s", channel_id.c_str(), blocked_channel_id.c_str());

    ChannelState* state = get_channel_state(channel_id);

    if (channel_id != prev_backup_channel_id) {
        printf("Received an ack from someone other than our backup!");
        any_failures = any_failures || true;
    }

    // Get request we expect
    std::map<std::string, BackupRequest>::iterator it = state->backup_requests.find(given_nonce);
    if (it == state->backup_requests.end()) {
        printf("Error! We didn't find the in-flight request!!");
        any_failures = any_failures || true;
    }

    struct BackupRequest backup_request = state->backup_requests[given_nonce];
    std::string backup_request_nonce(backup_request.nonce, NONCE_BYTE_LEN);
    state->backup_requests.erase(given_nonce);
    
    // check secure ack and nonce
    if (msg.result != BACKUP_STORE_ACK) {
        printf("ecall_verify_backup_stored: invalid ack response");
        any_failures = any_failures || true;
    }

    if (given_nonce != backup_request_nonce) {
        printf("The given ack nonce doesn't match the oldest backup request nonce!");
        printf("Given: %s, Expected: %s", given_nonce.c_str(), backup_request_nonce.c_str());
        any_failures = any_failures || true;
    }

    if (teechain_state == Backup) { // send secure ack to next node in the chain

        log_debug("We have just received an ack! Send ack to the next node in the chain!");
        ChannelState* next_state = get_channel_state(next_backup_channel_id);
        return send_secure_backup_ack(next_backup_channel_id, blocked_channel_id, backup_request_nonce, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }


    // We are the primary
    if (any_failures) {
        log_debug("We received a failure somewhere along the backup path!");
        memcpy(next_channel_id_to_send_on, blocked_channel_id.c_str(), CHANNEL_ID_LEN);
        return REQUEST_FAILED;

    } else if (backup_request.request_blocked_on == Channel_Create_Request) {
        log_debug("Send channel create ack! We are the primary and we got an ack from our backup!");
        return send_channel_create_ack(blocked_channel_id, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Add_Deposit_Request) {
        log_debug("Send add deposit request! We are the primary and we got an ack from our backup!");
        return send_add_deposit_request(blocked_channel_id, backup_request.deposit_id_blocked_on, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Add_Deposit_Ack) {
        log_debug("Send add deposit ack! We are the primary and we got an ack from our backup!");
        return send_add_deposit_ack(blocked_channel_id, backup_request_nonce, backup_request.deposit_id_blocked_on, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Remove_Deposit_Request) {
        log_debug("Send remove deposit request! We are the primary and we got an ack from our backup!");
        return send_remove_deposit_request(blocked_channel_id, backup_request.deposit_id_blocked_on, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Remove_Deposit_Ack) {
        log_debug("Send remove deposit ack! We are the primary and we got an ack from our backup!");
        return send_remove_deposit_ack(blocked_channel_id, backup_request_nonce, backup_request.deposit_id_blocked_on, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else if (backup_request.request_blocked_on == Backup_Store_Request) {
        printf("Send local ack! We are the primary and we got an ack from our backup!");
        return send_local_ack(blocked_channel_id, next_channel_id_to_send_on, send_action);
    }

    return REQUEST_CRASHED; // invalid message type
}

int ecall_remove_remote_backup(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context) {

    struct RemoveBackupMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct RemoveBackupMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    if (msg.request != REMOVE_BACKUP) {
        printf("invalid backup operation!");
        return 1;
    }
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    std::string given_channel_id(msg.backup_channel_id, CHANNEL_ID_LEN);
    ChannelState* state = get_channel_state(given_channel_id);

    if (given_channel_id != prev_backup_channel_id) {
        printf("Cannot remove this backup channel! It is not from the node behind me in the chain!");
        return 1;
    }

    // remove backup node
    prev_backup_channel_id = "";
    // TODO: erase backup state

    // construct secure ack remote party to know removed backup
    struct SecureAckMsg ack;
    uint32_t in_len = sizeof(struct SecureAckMsg);

    // fill message
    memcpy(ack.channel_id, given_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.nonce, given_nonce.c_str(), NONCE_BYTE_LEN);
    ack.result = BACKUP_REMOVE_ACK;

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &ack, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        //state->channel_state = Channel_Settled; // deadlock state
        return 1;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data_out, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    return 0;
}

int ecall_remove_backup(const char *channel_id, int channel_len, char* encrypted_data, int* len, char* p_gcm_mac) {
    std::string channel_id_s(channel_id, channel_len);

    if (!check_state(Backup)) {
        printf("I am not a backup node! Cannot remove me from a backup chain!");
        return 1;
    }

    if (have_backup()) {
        printf("I am not the last node in the backup chain! You can only remove the last node!");
        return 1;
    }

    if (channel_id_s != next_backup_channel_id) {
        printf("Invalid channel id to remove backup from backup chain!");
        return 1;
    }

    // remove backup state
    next_backup_channel_id = "";
    ChannelState* state = get_channel_state(channel_id_s);

    // prepare an encrypted message for the next backup and give it to untrusted side
    struct RemoveBackupMsg msg;
    uint32_t in_len = sizeof(struct RemoveBackupMsg);

    memcpy(msg.backup_channel_id, channel_id_s.c_str(), CHANNEL_ID_LEN);
    // generate random nonce for message freshness
    state->most_recent_nonce = generate_random_nonce();
    memcpy(msg.nonce, state->most_recent_nonce.c_str(), NONCE_BYTE_LEN);
    msg.request = REMOVE_BACKUP; 

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return 1;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *len = in_len;
    return 0;
}

static void backup_my_setup_transaction(BackupEnclaveStateMsg* msg) {
    struct BackupSetupTransactionStateMsg* setup_transaction_state = &(msg->my_setup_transaction);

    // fill my setup transaction state into backup message
    memcpy(setup_transaction_state->my_address, my_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
    setup_transaction_state->miner_fee = my_setup_transaction.miner_fee;
    setup_transaction_state->num_deposits = my_setup_transaction.deposit_ids_to_deposits.size();

    for (unsigned int i = 0; i < setup_transaction_state->num_deposits; i++) {
        Deposit deposit = my_setup_transaction.deposit_ids_to_deposits[i];
        if (!deposit.is_spent) {
            struct BackupDepositStateMsg* backup_deposit_state = &(setup_transaction_state->deposit_states[i]);
            memcpy(backup_deposit_state->private_key, deposit.private_key.c_str(), BITCOIN_PRIVATE_KEY_LEN);

            struct DepositStateMsg* deposit_state = &(backup_deposit_state->deposit_state);
            deposit_state->is_remote_deposit = false;

            memcpy(deposit_state->txid, deposit.txid.c_str(), BITCOIN_TX_HASH_LEN);
            deposit_state->tx_index = deposit.tx_index;
            deposit_state->deposit_amount = deposit.deposit_amount;
            deposit_state->deposit_id = i;  // required for backup tx generation

            deposit_state->deposit_script_length = deposit.script.length();
            memcpy(deposit_state->deposit_script, deposit.script.c_str(), deposit_state->deposit_script_length);
            memcpy(deposit_state->public_key, deposit.public_key.c_str(), BITCOIN_PUBLIC_KEY_LEN);
            memcpy(deposit_state->bitcoin_address, deposit.bitcoin_address.c_str(), BITCOIN_ADDRESS_LEN);
        }
    }
}

static void backup_deposits_in_channel(std::vector<unsigned long long> deposit_ids, std::map<unsigned long long, Deposit> deposit_ids_to_deposits, BackupChannelStateMsg* channel_state, int index_to_start_at, bool is_remote_deposit) {
        for (unsigned int i = 0; i < deposit_ids.size(); i++) {
            unsigned long long deposit_id = deposit_ids[i];
            Deposit deposit = deposit_ids_to_deposits[deposit_id];

            struct BackupDepositStateMsg* backup_deposit_state = &(channel_state->deposit_states[i + index_to_start_at]);

            // fill deposit
            memcpy(backup_deposit_state->private_key, deposit.private_key.c_str(), BITCOIN_PRIVATE_KEY_LEN);

            struct DepositStateMsg* deposit_state = &(backup_deposit_state->deposit_state);
            memcpy(deposit_state->txid, deposit.txid.c_str(), BITCOIN_TX_HASH_LEN);
            deposit_state->tx_index = deposit.tx_index;
            deposit_state->deposit_amount = deposit.deposit_amount;
            deposit_state->deposit_id = deposit_id;  // required for backup tx generation

            deposit_state->deposit_script_length = deposit.script.length();
            memcpy(deposit_state->deposit_script, deposit.script.c_str(), deposit_state->deposit_script_length);
            memcpy(deposit_state->public_key, deposit.public_key.c_str(), BITCOIN_PUBLIC_KEY_LEN);
            memcpy(deposit_state->bitcoin_address, deposit.bitcoin_address.c_str(), BITCOIN_ADDRESS_LEN);
            deposit_state->is_remote_deposit = is_remote_deposit;
        }
}

static void backup_my_channels(BackupEnclaveStateMsg* msg) {
    std::vector<std::string> channel_ids = get_all_non_backup_channel_ids();
    
    // fill channel states for backup
    msg->num_channels = channel_ids.size();

    for (unsigned int i = 0; i < msg->num_channels; i++) {
        struct BackupChannelStateMsg* channel_state = &(msg->channel_states[i]);

        std::string channel_id = channel_ids[i];
        ChannelState* state = get_channel_state(channel_id);

        // fill channel state
        memcpy(channel_state->channel_id, channel_id.c_str(), CHANNEL_ID_LEN);
        channel_state->balance_a = state->my_balance;
        channel_state->balance_b = state->remote_balance;
        memcpy(channel_state->bitcoin_address_a, my_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
        memcpy(channel_state->bitcoin_address_b, state->remote_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);

        // fill deposits in channel
        std::vector<unsigned long long> my_deposit_indexes = find_deposit_ids_in_channel(channel_id, my_setup_transaction.deposit_ids_to_channels);
        std::vector<unsigned long long> remote_deposit_indexes = find_deposit_ids_in_channel(channel_id, state->remote_setup_transaction.deposit_ids_to_channels);
        backup_deposits_in_channel(my_deposit_indexes, my_setup_transaction.deposit_ids_to_deposits, channel_state, 0, false);
        backup_deposits_in_channel(remote_deposit_indexes, state->remote_setup_transaction.deposit_ids_to_deposits, channel_state, my_deposit_indexes.size(), true);
        channel_state->num_deposits = my_deposit_indexes.size() + remote_deposit_indexes.size();
    }
}

struct BackupEnclaveStateMsg generate_backup_message_for_storage(std::string nonce) {
    struct BackupEnclaveStateMsg msg;
    uint32_t in_len = sizeof(struct BackupEnclaveStateMsg);

    if (teechain_state == Funded) {
        backup_my_setup_transaction(&msg);
        backup_my_channels(&msg);
    } else if (teechain_state == Backup) {
        msg = most_recent_backup_state;
    }

    //TODO: implement real support for monotonic counters
    //memcpy(msg.nonce, nonce.c_str(), NONCE_BYTE_LEN);
    return msg;
}

struct BackupEnclaveStateMsg generate_backup_message(std::string backup_channel_id, std::string blocked_channel_id, BackupRequest blocked_request, bool any_failures) {
    ChannelState* state = get_channel_state(backup_channel_id);

    // prepare an encrypted message for the backup and give it to untrusted side
    struct BackupEnclaveStateMsg msg;
    uint32_t in_len = sizeof(struct BackupEnclaveStateMsg);

    if (teechain_state == Funded) {
        // fill message with my state and send
        backup_my_setup_transaction(&msg);
        backup_my_channels(&msg);
    } else if (teechain_state == Backup) {
        msg = most_recent_backup_state;
    }

    // fill blocked channel and backup request information
    memcpy(msg.backup_channel_id, backup_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(msg.blocked_channel_id, blocked_channel_id.c_str(), CHANNEL_ID_LEN);
    msg.blocked_request = blocked_request;
    msg.any_failures = any_failures;

    return msg;
}

int ecall_get_backup_data_encrypted(const char *channel_id, int channel_len, char* encrypted_data, int* len, char* p_gcm_mac) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState* state = get_channel_state(channel_id_s);

    if (channel_id_s != prev_backup_channel_id) {
        printf("Given channel id: %s", channel_id_s.c_str());
        printf("Prev channel id: %s", prev_backup_channel_id.c_str());
        printf("Cannot send my backup state along this channel! It is not my backup node channel!");
        return 1;
    }

    // Create backup request for channel create
    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Channel_Create_Request;
    // We ignore the generated nonce here -- this ecall is called on backup channel creation (no ack for the nonce is required)
    memcpy(backup_request.nonce, generate_random_nonce().c_str(), NONCE_BYTE_LEN);

    struct BackupEnclaveStateMsg msg = generate_backup_message(channel_id_s, channel_id_s, backup_request, false);
    uint32_t in_len = sizeof(struct BackupEnclaveStateMsg);

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return 1;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *len = in_len;
    return 0;
}

static void print_backup_deposit_state(struct BackupDepositStateMsg deposit) {
        printf("\tBackup deposit state: %s, %llu, %llu, %s", std::string(deposit.deposit_state.txid, BITCOIN_TX_HASH_LEN).c_str(), deposit.deposit_state.tx_index, deposit.deposit_state.deposit_amount, std::string(deposit.deposit_state.deposit_script, deposit.deposit_state.deposit_script_length).c_str());
        printf("\tBackup deposit bitcoin state: %s, %s, %s", std::string(deposit.deposit_state.public_key, BITCOIN_PUBLIC_KEY_LEN).c_str(), std::string(deposit.deposit_state.bitcoin_address, BITCOIN_ADDRESS_LEN).c_str(), std::string(deposit.private_key, BITCOIN_PRIVATE_KEY_LEN).c_str());
}

void print_backup_state(struct BackupEnclaveStateMsg msg) {
    printf("PRINTING BACKUP ENCLAVE STATE:");
    printf("Backup channel: %s", std::string(msg.backup_channel_id, CHANNEL_ID_LEN).c_str());
    printf("Blocked channel: %s", std::string(msg.blocked_channel_id, CHANNEL_ID_LEN).c_str());
    printf("Backup setup transaction address: %s", std::string(msg.my_setup_transaction.my_address, BITCOIN_ADDRESS_LEN).c_str());

    printf("PRINTING SETUP DEPOSIT STATES");
    unsigned long long num_deposits = msg.my_setup_transaction.num_deposits;
    for (unsigned int i = 0; i < num_deposits; i++) {
        printf("\tSetup deposit number: %d", i);
        print_backup_deposit_state(msg.my_setup_transaction.deposit_states[i]);
    }

    printf("PRINTING CHANNEL STATES");
    unsigned long long num_channels = msg.num_channels;
    for (unsigned int i = 0; i < num_channels; i++) {
        printf("\tBackup channel number: %d", i);
        struct BackupChannelStateMsg channel = msg.channel_states[i];

        printf("\tBackup channel state: %s, %llu, %llu, %s, %s", std::string(channel.channel_id, CHANNEL_ID_LEN).c_str(), channel.balance_a, channel.balance_b, std::string(channel.bitcoin_address_a, BITCOIN_ADDRESS_LEN).c_str(), std::string(channel.bitcoin_address_b, BITCOIN_ADDRESS_LEN).c_str());

        unsigned long long num_deposits = channel.num_deposits;
        for (unsigned int i = 0; i < num_deposits; i++) {
            printf("\tChannel deposit number: %d", i);
            print_backup_deposit_state(channel.deposit_states[i]);
        }
    }
}

static bool verify_backup_request(struct BackupEnclaveStateMsg backup_msg) {
    struct BackupRequest backup_request = backup_msg.blocked_request;

    if (backup_request.request_blocked_on == Add_Deposit_Request ||
            backup_request.request_blocked_on == Remove_Deposit_Request) {
        unsigned long long deposit_index = backup_request.deposit_id_blocked_on;
        
        // check deposit_index is not already spent
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits = extract_deposit_mapping_from_backup();

        if (deposit_ids_to_deposits.find(deposit_index) == deposit_ids_to_deposits.end()) {
            printf("Invalid deposit index given for backup request!");
            return false;
        } else {
            Deposit deposit = deposit_ids_to_deposits[deposit_index];
            if (deposit.is_spent) {
                printf("The deposit is already spent! Cannot allow it to be moved into/out of a channel!");
                return false;
            }
        } 
    }

    if (backup_request.request_blocked_on == Send_Bitcoin_Request ||
            backup_request.request_blocked_on == Receive_Bitcoin_Request) {
        // check channel state is not already settled
    }

    return true;
}

int ecall_store_encrypted_backup_data(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char* next_channel_id_to_send_on, int* send_action) {

    struct BackupEnclaveStateMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct BackupEnclaveStateMsg), (unsigned char*) &msg)) {
        return REQUEST_FAILED; // decryption failed
    }

    std::string given_channel_id(msg.backup_channel_id, CHANNEL_ID_LEN);
    std::string blocked_channel_id(msg.blocked_channel_id, CHANNEL_ID_LEN);
    std::string given_nonce(msg.blocked_request.nonce, NONCE_BYTE_LEN);
    bool any_failures = msg.any_failures;

    if (given_channel_id != next_backup_channel_id) {
        printf("Cannot accept this backup state! It is not from the node that I am trying to backup!");
        printf("Given channel: %s, Expected channel: %s", given_channel_id.c_str(), next_backup_channel_id.c_str());
        any_failures = any_failures || true;
    }

    most_recent_backup_state = msg;
    //print_backup_state(most_recent_backup_state);

    ChannelState* state = get_channel_state(given_channel_id);

    if (!have_existing_backup_state()) {
        printf("This is the first backup state we are given! This happens when my backup is initialized!");
        // First time we are storing a backup state
        saved_first_backup_state = true;
        return send_local_ack(given_channel_id, next_channel_id_to_send_on, send_action);
    }

    // I am being asked to backup and ack securely
    if (!have_backup()) { // I have no backups -- send ack!
        printf("I don't have any backups! Sending secure ack after storing state!");
        return send_secure_backup_ack(next_backup_channel_id, blocked_channel_id, given_nonce, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    // wait for backup to ack for this request before responding
    printf("Waiting for my backups to ack this new state to store!");
    std::string nonce(msg.blocked_request.nonce, NONCE_BYTE_LEN);

    // save the request to our backup state
    struct BackupRequest backup_request = msg.blocked_request;
    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_backup_store_request(blocked_channel_id, backup_request, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

static bool update_channel_data(struct UpdateChannelBalanceMsg* msg) {
    std::string update_channel_id(msg->blocked_channel_id, CHANNEL_ID_LEN);

    for (unsigned int i = 0; i < most_recent_backup_state.num_channels; i++) {
        struct BackupChannelStateMsg* channel_state = &(most_recent_backup_state.channel_states[i]);
        std::string stored_channel_id(channel_state->channel_id, CHANNEL_ID_LEN);

        if (update_channel_id == stored_channel_id) {
            channel_state->balance_a = msg->my_balance;
            channel_state->balance_b = msg->remote_balance;
            memcpy(channel_state->bitcoin_address_a, msg->my_bitcoin_address, BITCOIN_ADDRESS_LEN);
            memcpy(channel_state->bitcoin_address_b, msg->remote_bitcoin_address, BITCOIN_ADDRESS_LEN);
            return true;
        }

    }

    return false;
}

int ecall_store_encrypted_channel_update_data(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char* next_channel_id_to_send_on, int* send_action) {

    struct UpdateChannelBalanceMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct UpdateChannelBalanceMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    std::string given_channel_id(msg.backup_channel_id, CHANNEL_ID_LEN);
    std::string blocked_channel_id(msg.blocked_channel_id, CHANNEL_ID_LEN);
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    bool any_failures = msg.any_failures;

    if (given_channel_id != next_backup_channel_id) {
        printf("Cannot accept this backup state! It is not from the node that I am trying to backup!");
        printf("Given channel: %s, Expected channel: %s", given_channel_id.c_str(), next_backup_channel_id.c_str());
        any_failures = any_failures || true;
    }

    // Store most recent backup store
    most_recent_channel_update_state = msg;
    if (!update_channel_data(&msg)) {
        printf("Unable to update channel state with new balances! Channel state not found!");
        any_failures = any_failures || true;
    }

    ChannelState* state = get_channel_state(given_channel_id);

    // I am being asked to backup and ack securely
    if (!have_backup()) { // I have no backups -- send ack!
        if (!benchmark) {
            printf("I don't have any backups! Sending secure ack after storing state!");
        }
        return send_secure_update_channel_ack(next_backup_channel_id, blocked_channel_id, given_nonce, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    // wait for backup to ack for this request before responding
    if (!benchmark) {
        printf("Waiting for my backups to ack this new channel state to store!");
    }
    std::string nonce(msg.nonce, NONCE_BYTE_LEN);

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Backup_Store_Request;
    memcpy(backup_request.nonce, msg.nonce, NONCE_BYTE_LEN);

    // save the request to our backup state
    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_update_channel_balance_request(blocked_channel_id, nonce, any_failures, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}
