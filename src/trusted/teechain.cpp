#include <cstdlib>
#include <cerrno>
#include <climits>
#include <stdexcept>
#include <stdarg.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <stdexcept>

#include <univalue.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <random.h>

#include "backups.h"
#include "rpc.h"
#include "core_io.h"
#include "teechain.h"
#include "teechain_t.h"
#include "utils.h"

#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

#include "service_provider.h"
#include "ecp.h"
#include "ias_ra.h"

#include "channel.h"
#include "network.h"
#include "state.h"
#include "utils.h"

// User messages to display after operations return
std::map<std::string, std::string> channel_ids_to_user_outputs;

// Provided by backup modules
extern bool saved_first_backup_state;
extern struct BackupEnclaveStateMsg most_recent_backup_state;

// Globals for teechain enclave
bool testnet = true;
bool debug = false;
bool benchmark = false;

// Global setup transaction for this enclave
SetupTransaction my_setup_transaction;

// Declarations to avoid circular dependencies:
bool lock_channel(ChannelState* channel);
int sgx_encrypt(ChannelState *state, unsigned char *plain, int plainlen, unsigned char *cypher, sgx_aes_gcm_128bit_tag_t *p_out_mac);
int sgx_decrypt(unsigned char *cypher, int cypherlen, unsigned char *p_gcm_mac, sgx_ra_context_t context, unsigned char *plain);
std::string generate_random_nonce();

bool check_deposits_verified(ChannelState* state) {
    return state->deposits_verified && state->other_party_deposits_verified;
}

static bool is_deposit_spent(int deposit_id) {
    std::map<unsigned long long, Deposit>::iterator it;
    it = my_setup_transaction.deposit_ids_to_deposits.find(deposit_id);
    if (it != my_setup_transaction.deposit_ids_to_deposits.end()) {
        if (it->second.is_spent) {
	    return true;
        }
    }
    return false;
}

static bool is_deposit_in_use(int deposit_id) {
    std::map<unsigned long long, std::string>::iterator it;
    it = my_setup_transaction.deposit_ids_to_channels.find(deposit_id);
    if (it != my_setup_transaction.deposit_ids_to_channels.end()) {
        return true;
    }
    return false;
}

unsigned long long calculate_total_fee(unsigned long long fee_per_byte, int num_inputs, int num_outputs) {
    return fee_per_byte * ((num_inputs * 180) + (num_outputs * 34) + 10 - num_inputs);  // this is a heuristic
}

std::string create_raw_transaction_rpc() {
    std::string create_transaction_rpc = "";
    if (testnet) {
        create_transaction_rpc += "-testnet ";
    }
    create_transaction_rpc += "createrawtransaction ";
    return create_transaction_rpc;
}

std::string sign_raw_transaction_rpc() {
    std::string sign_transaction_rpc = "";
    if (testnet) {
        sign_transaction_rpc += "-testnet ";
    }
    sign_transaction_rpc += "signrawtransaction ";
    return sign_transaction_rpc;
}

std::string decode_raw_transaction_rpc() {
    std::string decode_transaction_rpc = "";
    if (testnet) {
        decode_transaction_rpc += "-testnet ";
    }
    decode_transaction_rpc += "decoderawtransaction ";
    return decode_transaction_rpc;
}

std::vector<unsigned long long> find_deposit_ids_in_channel(std::string channel_id,
        std::map<unsigned long long, std::string> deposit_ids_to_channels) {

    std::map<unsigned long long, std::string>::const_iterator it;
    std::vector<unsigned long long> deposit_ids;

    for (it = deposit_ids_to_channels.begin(); it != deposit_ids_to_channels.end(); it++) {
        if (it->second == channel_id) {
            deposit_ids.push_back(it->first);
        }
    }

    return deposit_ids;
}

static Deposit create_deposit_from_deposit_backup(BackupDepositStateMsg backup_deposit_state) {
    DepositStateMsg deposit_state = backup_deposit_state.deposit_state;

    // Create new Deposit from previous state
    Deposit deposit;
    deposit.txid = std::string(deposit_state.txid, BITCOIN_TX_HASH_LEN);
    deposit.tx_index = deposit_state.tx_index;
    deposit.deposit_amount = deposit_state.deposit_amount;

    deposit.bitcoin_address = std::string(deposit_state.bitcoin_address, BITCOIN_ADDRESS_LEN);
    deposit.public_key = std::string(deposit_state.public_key, BITCOIN_PUBLIC_KEY_LEN);
    deposit.private_key = std::string(backup_deposit_state.private_key, BITCOIN_PRIVATE_KEY_LEN); 
    deposit.script = std::string(deposit_state.deposit_script, deposit_state.deposit_script_length);

    return deposit;
}

std::map<unsigned long long, Deposit> extract_remote_deposit_mapping_from_backup() {
    std::map<unsigned long long, Deposit> deposit_mapping;

    // Create mapping from backup state and insert them into the map
    for (unsigned int i = 0; i < most_recent_backup_state.num_channels; i++) {
        BackupChannelStateMsg channel_state = most_recent_backup_state.channel_states[i];
        std::string channel_id(channel_state.channel_id, CHANNEL_ID_LEN);
        //printf("Looking at the deposits in channel: %s", channel_id.c_str()); 
        for (unsigned int d = 0; d < channel_state.num_deposits; d++) {
            BackupDepositStateMsg backup_deposit_state = channel_state.deposit_states[d];
            bool is_remote_deposit = backup_deposit_state.deposit_state.is_remote_deposit;

            if (is_remote_deposit) {
                // Add mapping
                deposit_mapping[backup_deposit_state.deposit_state.deposit_id] = create_deposit_from_deposit_backup(backup_deposit_state); 
            }
        }
    }
    
    return deposit_mapping;
}

std::map<unsigned long long, Deposit> extract_deposit_mapping_from_backup() {
    std::map<unsigned long long, Deposit> deposit_mapping;

    // Create deposits from backup state and insert them into the map
    BackupSetupTransactionStateMsg setup_transaction = most_recent_backup_state.my_setup_transaction;
    for (unsigned int i = 0; i < setup_transaction.num_deposits; i++) {
        BackupDepositStateMsg backup_deposit_state = setup_transaction.deposit_states[i];

        // Add mapping
        deposit_mapping[backup_deposit_state.deposit_state.deposit_id] = create_deposit_from_deposit_backup(backup_deposit_state); 
    }
    
    return deposit_mapping;
}

static std::map<unsigned long long, std::string> extract_deposit_channel_mapping_from_backup(bool for_remote) {
    std::map<unsigned long long, std::string> deposit_channel_mapping;

    // Create mapping from backup state and insert them into the map
    for (unsigned int i = 0; i < most_recent_backup_state.num_channels; i++) {
        BackupChannelStateMsg channel_state = most_recent_backup_state.channel_states[i];
        std::string channel_id(channel_state.channel_id, CHANNEL_ID_LEN);
        //printf("Looking at the deposits in channel: %s", channel_id.c_str()); 
        for (unsigned int d = 0; d < channel_state.num_deposits; d++) {
            BackupDepositStateMsg backup_deposit_state = channel_state.deposit_states[d];
            bool is_remote_deposit = backup_deposit_state.deposit_state.is_remote_deposit;

            if (for_remote && is_remote_deposit) {  // only include remote deposits
                    // Add mapping
                    deposit_channel_mapping[backup_deposit_state.deposit_state.deposit_id] = channel_id;
                    //printf("Channel ID: %s, has remote deposit index: %d", channel_id.c_str(), d);        
    
            } else if (!for_remote && !is_remote_deposit) {
                    // Add mapping
                    deposit_channel_mapping[backup_deposit_state.deposit_state.deposit_id] = channel_id;
                    //printf("Channel ID: %s, has remote deposit index: %d", channel_id.c_str(), d);        

            }
        }
    }
    
    return deposit_channel_mapping;
}

static std::vector<unsigned long long> find_unused_deposits(
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::map<unsigned long long, std::string> deposit_ids_to_channels) {

    std::map<unsigned long long, Deposit>::const_iterator it;
    std::vector<unsigned long long> deposit_ids;

    for (it = deposit_ids_to_deposits.begin(); it != deposit_ids_to_deposits.end(); it++) {
        if ((deposit_ids_to_channels.find(it->first) == deposit_ids_to_channels.end()) && !(it->second.is_spent)) {
            // deposit not in any channel and not spent
            deposit_ids.push_back(it->first);
        }
    }

    return deposit_ids;
}

static unsigned long long sum_unused_deposits(std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::vector<unsigned long long> unused_deposit_ids) {
    unsigned long long sum = 0;

    for (unsigned int i = 0; i < unused_deposit_ids.size(); i++) {
        unsigned long long deposit_id = unused_deposit_ids[i];
        Deposit deposit = deposit_ids_to_deposits[deposit_id];
        sum += deposit.deposit_amount;
    }

    return sum;
}

void remove_deposit_from_channel(unsigned long long deposit_id,
        std::map<unsigned long long, std::string>* deposit_ids_to_channels) {
    std::map<unsigned long long, std::string>::iterator it = deposit_ids_to_channels->find(deposit_id);
    deposit_ids_to_channels->erase(it);
}

unsigned long long get_total_deposit_amount_in_channel(std::string channel_id,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::map<unsigned long long, std::string> deposit_ids_to_channels) {

    unsigned long long total = 0;
    std::vector<unsigned long long> depositIndexesInChannel = find_deposit_ids_in_channel(channel_id, deposit_ids_to_channels);
    for (unsigned long long deposit_id : depositIndexesInChannel) {
        total += deposit_ids_to_deposits[deposit_id].deposit_amount;
    }

    return total;
}

// fill the deposit state message with the given deposit and txid
void fill_deposits_into_channel_state_message(std::vector<unsigned long long> deposit_ids, std::map<unsigned long long, Deposit> deposit_ids_to_deposits, struct ChannelStateMsg* channel_state, unsigned int index_to_start_at) {
 
    for (unsigned int i = 0; i < deposit_ids.size(); i++) {
        unsigned long long deposit_id = deposit_ids[i];
        Deposit deposit = deposit_ids_to_deposits[deposit_id];
        
        // create and fill depositStateMsg
        struct DepositStateMsg depositStateMsg;
        memcpy(depositStateMsg.txid, deposit.txid.c_str(), BITCOIN_TX_HASH_LEN);
        depositStateMsg.tx_index = deposit_id;
        depositStateMsg.deposit_amount = deposit.deposit_amount;
        depositStateMsg.deposit_id = deposit_id;

        memcpy(depositStateMsg.public_key, deposit.public_key.c_str(), BITCOIN_PUBLIC_KEY_LEN);
        memcpy(depositStateMsg.bitcoin_address, deposit.bitcoin_address.c_str(), BITCOIN_ADDRESS_LEN);
        depositStateMsg.deposit_script_length = deposit.script.length();
        memcpy(depositStateMsg.deposit_script, deposit.script.c_str(), depositStateMsg.deposit_script_length);

        // save depositStateMsg
        memcpy(&channel_state->deposit_states[index_to_start_at + i], &depositStateMsg, sizeof(struct DepositStateMsg));
    }
}

// fills the empty channel state message with my channel state for the channel id
void fill_empty_channel_state(struct ChannelStateMsg* channelState) {
    // check given channel id matches one of my channels
    std::string given_channel_id(channelState->channel_id, CHANNEL_ID_LEN);
    
    ChannelState* state = get_channel_state(given_channel_id);
    if (state == NULL) {
        printf("Invalid channel id given! I do not have the channel to route through..");
        return;
    }

    // fill channel state message
    channelState->balance_a = state->my_balance;
    channelState->balance_b = state->remote_balance;
    memcpy(channelState->bitcoin_address_a, my_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
    memcpy(channelState->bitcoin_address_b, state->remote_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);
    
    // fill my deposits into channel state message
    std::vector<unsigned long long> my_deposit_ids = find_deposit_ids_in_channel(given_channel_id, my_setup_transaction.deposit_ids_to_channels);
    fill_deposits_into_channel_state_message(my_deposit_ids, my_setup_transaction.deposit_ids_to_deposits, channelState, 0 /* index to start at */);

    // fill remote deposits into channel state message
    std::vector<unsigned long long> remote_deposits = find_deposit_ids_in_channel(given_channel_id, state->remote_setup_transaction.deposit_ids_to_channels);
    fill_deposits_into_channel_state_message(remote_deposits, state->remote_setup_transaction.deposit_ids_to_deposits, channelState, my_deposit_ids.size());

    channelState->num_deposits = my_deposit_ids.size() + remote_deposits.size();
}

int send_local_ack(std::string given_channel_id, char* next_channel_id_to_send_on, int* send_action) {
    // no need for encrypted message -- just notify untrusted to ack local rpc client
    memcpy(next_channel_id_to_send_on, given_channel_id.c_str(), CHANNEL_ID_LEN); // use the operation channel to send ack
    *send_action = SEND_LOCAL_ACK;

    return 0;
}

int send_channel_create_ack(std::string given_channel_id, char* next_channel_id_to_send_on, int* send_action) {
    // no need for encrypted message -- just notify untrusted to ack local rpc client
    memcpy(next_channel_id_to_send_on, given_channel_id.c_str(), CHANNEL_ID_LEN); // use the operation channel to send ack
    *send_action = SEND_CHANNEL_CREATE_ACK;

    return 0;
}

int send_receive_ack(std::string given_channel_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    // no need for encrypted message -- just ack remote in channel insecurely
    ChannelState* state = get_channel_state(given_channel_id);
    memcpy(next_channel_id_to_send_on, given_channel_id.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_INSECURE_ACK;

    return 0;
}

int send_bitcoin_payment_message(std::string given_channel_id, unsigned long long amount, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(given_channel_id);

    // prepare an encrypted send message for the remote and give it to untrusted side
    struct SendMsg msg;
    uint32_t in_len = sizeof(struct SendMsg);

    // fill message
    state->my_monotonic_counter += 1;
    state->my_sends += 1;

    msg.monotoniccount = state->my_monotonic_counter;
    msg.amount = amount;

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        //state->channel_state = Channel_Settled; // deadlock state
        return 1;
    }

    // copy out to untrusted memory
    std::memcpy(encrypted_data_out, outbuf, in_len);
    std::memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    std::memcpy(next_channel_id_to_send_on, given_channel_id.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_BITCOIN_PAYMENT;

    return 0;
}
    
int send_add_deposit_ack(std::string channel_id_s, std::string given_nonce, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(channel_id_s);
    unsigned long long amount_to_add = state->remote_setup_transaction.deposit_ids_to_deposits[deposit_id].deposit_amount;
    
    // construct secure ack remote party to know removed deposit from the channel
    struct SecureAckMsg ack;
    uint32_t in_len = sizeof(struct SecureAckMsg);

    // fill message
    memcpy(ack.channel_id, channel_id_s.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.nonce, given_nonce.c_str(), NONCE_BYTE_LEN);
    ack.result = ADD_DEPOSIT_ACK;

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
    std::memcpy(next_channel_id_to_send_on, channel_id_s.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_DEPOSIT_ADD_ACK;
    return 0; 
}

int send_remove_deposit_ack(std::string channel_id_s, std::string given_nonce, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(channel_id_s);
    unsigned long long amount_to_remove = state->remote_setup_transaction.deposit_ids_to_deposits[deposit_id].deposit_amount;
    
    // construct secure ack remote party to know removed deposit from the channel
    struct SecureAckMsg ack;
    uint32_t in_len = sizeof(struct SecureAckMsg);

    // fill message
    memcpy(ack.channel_id, channel_id_s.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.nonce, given_nonce.c_str(), NONCE_BYTE_LEN);
    ack.result = REMOVE_DEPOSIT_ACK;

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
    std::memcpy(next_channel_id_to_send_on, channel_id_s.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_DEPOSIT_REMOVE_ACK;
    return 0; 
}

int send_remove_deposit_request(std::string channel_id_s, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(channel_id_s);

    // generate random nonce for message freshness
    state->most_recent_nonce = generate_random_nonce();

    // prepare an encrypted message for the remote and give it to untrusted side
    struct DepositMsg msg;
    uint32_t in_len = sizeof(struct DepositMsg);

    // fill message
    msg.deposit_operation = REMOVE_DEPOSIT;
    memcpy(msg.nonce, state->most_recent_nonce.c_str(), NONCE_BYTE_LEN);
    memcpy(msg.channel_id, channel_id_s.c_str(), CHANNEL_ID_LEN);
    msg.deposit_id = deposit_id;

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return REQUEST_CRASHED;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data_out, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    std::memcpy(next_channel_id_to_send_on, channel_id_s.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_DEPOSIT_REMOVE_REQUEST;

    return 0; 

}

int send_add_deposit_request(std::string channel_id_s, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(channel_id_s);

    // generate random nonce for message freshness
    state->most_recent_nonce = generate_random_nonce();

    // prepare an encrypted message for the remote and give it to untrusted side
    struct DepositMsg msg;
    uint32_t in_len = sizeof(struct DepositMsg);

    // fill message
    msg.deposit_operation = ADD_DEPOSIT;
    memcpy(msg.nonce, state->most_recent_nonce.c_str(), NONCE_BYTE_LEN);
    memcpy(msg.channel_id, channel_id_s.c_str(), CHANNEL_ID_LEN);
    msg.deposit_id = deposit_id;

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        return REQUEST_CRASHED;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data_out, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *encrypted_data_out_len = in_len;
    std::memcpy(next_channel_id_to_send_on, channel_id_s.c_str(), CHANNEL_ID_LEN);
    *send_action = SEND_DEPOSIT_ADD_REQUEST;

    return 0; 
}

int send_secure_update_channel_ack(std::string given_channel_id, std::string blocked_channel_id, std::string given_nonce, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    ChannelState* state = get_channel_state(given_channel_id);

    // construct secure ack
    struct BackupStoredAckMsg ack;
    uint32_t in_len = sizeof(struct BackupStoredAckMsg);

    // fill message
    memcpy(ack.channel_id, given_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.blocked_channel_id, blocked_channel_id.c_str(), CHANNEL_ID_LEN);
    memcpy(ack.nonce, given_nonce.c_str(), NONCE_BYTE_LEN);
    ack.result = CHANNEL_UPDATE_ACK;
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
    *send_action = SEND_UPDATE_CHANNEL_BALANCE_ACK;

    return 0;
}

UniValue sign_setup_transaction() {
    std::string prevout = "[{\"txid\":\"" + my_setup_transaction.utxo_hash + "\",\"vout\":" + TOSTR(my_setup_transaction.utxo_index) + ",\"scriptPubKey\":\"" + my_setup_transaction.utxo_script + "\",\"redeemScript\":\"\"}]";
    std::string privkey = "[\"" + my_setup_transaction.private_key + "\"]";

    std::string sign_transaction_rpc = sign_raw_transaction_rpc();
    sign_transaction_rpc += my_setup_transaction.setup_transaction_hash + " " + prevout + " " + privkey + " ALL";
    return executeCommand(sign_transaction_rpc);
}

UniValue decode_transaction(std::string transaction_hex) {
    std::string decode_transaction_rpc = decode_raw_transaction_rpc();
    decode_transaction_rpc += transaction_hex;
    return executeCommand(decode_transaction_rpc);
}

int ecall_setup_deposits(unsigned long long num_deposits, char* user_output) {
    if (!check_state(Primary)) {
	printf("Cannot setup deposits; this enclave is not a primary!");
        return 1;
    }

    // initialize ECC State for Bitcoin Library
    initializeECCState();
    
     std::string output("Please generate bitcoin funding transactions that deposit funds into the following Bitcoin addresses.\n");

     output += "For each of the Bitcoin addresses generated below, you'll have the chance to specify the transaction id, unspent transaction output, and the amount deposited into that address in the next step of the protocol.\n";

    // generate and print bitcoin addresses to be paid into by the user
    for (unsigned long long i = 0; i < num_deposits; i++) {
        // create new deposit
        Deposit deposit;
        deposit.is_spent = false;
        deposit.deposit_amount = 0;

        // generate new bitcoin pub/private key and address
        CKey key;
        key.MakeNewKey(true /* compressed */);
        CPubKey pubkey = key.GetPubKey();

        CKeyID keyid = pubkey.GetID();
        CTxDestination* dest = new CTxDestination;
        dest->class_type = 2;
        dest->keyID = &keyid;
        CScript script = GetScriptForDestination(*dest);

        // get redeem script
        std::string script_asm = ScriptToAsmStr(script);

        // TODO: clean up using the bitcoin core code! For now this works as we hardcode the redeem scripts...
        std::string redeem_script;
        if (debug) {
            redeem_script = "76a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac"; // hard coded for tests!
        } else {
            std::string hash_string = script_asm.substr(18, 40); // 18 is offset of hash in asm, 40 is length of RIPEMD160 in hex
            redeem_script = "76a914" + hash_string + "88ac";  // the P2PKH script format
        }

        CBitcoinAddress address;
        address.Set(pubkey.GetID());

        std::string generated_bitcoin_address = address.ToString();
        std::string generated_public_key = HexStr(key.GetPubKey());
        std::string generated_private_key = CBitcoinSecret(key).ToString();

        // save generated public/private keys to deposit
        deposit.bitcoin_address = generated_bitcoin_address;
        deposit.public_key = generated_public_key;
        deposit.private_key = generated_private_key;
        deposit.script = redeem_script;

        // assign deposit to setup deposit index
        my_setup_transaction.deposit_ids_to_deposits[i] = deposit;
        output += "Please deposit into bitcoin address " + generated_bitcoin_address + "\n";
    }

    teechain_state = WaitingForFunds;

    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}


int ecall_deposits_made(const char* address, int address_len, unsigned long long miner_fee, unsigned long long num_deposits, const char* txids, int txids_len, unsigned long long* tx_indexes, int tx_indexes_len, unsigned long long* deposit_amounts, int deposit_amounts_len, char* user_output) {
    if (!check_state(WaitingForFunds)) {
	printf("Cannot make the deposits into the enclave; setup deposits hasn't been called!");
        return 1;
    }

    if (num_deposits != my_setup_transaction.deposit_ids_to_deposits.size()) {
        printf("Number of deposits made does not match the number given to ecall_setup_deposits");
        return 1;
    }

    // Store enclave state for Setup transaction
    my_setup_transaction.my_address = std::string(address, address_len);
    my_setup_transaction.miner_fee = miner_fee;

    // store deposit information for setup transaction and 
    for (unsigned long long i = 0; i < num_deposits; i++) {
        // Update deposit amount and script
        Deposit* deposit = &(my_setup_transaction.deposit_ids_to_deposits[i]);

        std::string txid = std::string(&txids[i * BITCOIN_TX_HASH_LEN], BITCOIN_TX_HASH_LEN);
        deposit->txid = txid;
        deposit->tx_index = tx_indexes[i];
        deposit->deposit_amount = deposit_amounts[i];
    }

    teechain_state = Funded;

    std::string output = "Loaded your " + TOSTR(num_deposits) + " funding deposits into the Enclave.\n";
    output += "You are ready to begin creating channels!\n";
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}


void update_backup_channels(bool is_initiator, std::string channel_id) {
    if (is_initiator) {
        next_backup_channel_id = channel_id;
    } else {
        prev_backup_channel_id = channel_id;
    }
}

int ecall_channel_id_generated(const char *channel_id, int channel_len, bool is_backup) {
    if (!check_state(Funded) && !check_state(Backup)) {
	printf("Cannot set the channel id; this enclave is not in the correct state!");
        return 1;
    }

    std::string channel_id_s(channel_id, channel_len);
    std::string temp_id_s(TEMPORARY_CHANNEL_ID, CHANNEL_ID_LEN);

    // update channel id 
    ChannelState* state = get_channel_state(temp_id_s);
    remove_association(temp_id_s);
    associate_channel_state(channel_id_s, state);

    if (is_backup) {
        update_backup_channels(state->is_initiator, channel_id_s);
        // write user output
        std::string output = "A backup channel has been created!\n";
        output += "Backup Channel ID: " + channel_id_s + "\n";
        channel_ids_to_user_outputs[channel_id_s] = output;
    }
    return 0;
}

int ecall_create_new_channel(const char *channel_id, int channel_len, bool initiator) {
    if (!check_state(Funded)) {
	printf("Cannot create new channel; this enclave is not funded!");
        return 1;
    }

    std::string channel_id_s(channel_id, channel_len);

    // create channel state
    ChannelState* state = create_channel_state();
    state->is_initiator = initiator;
    state->is_backup_channel = false;
    associate_channel_state(channel_id_s, state);

    // update balance
    state->my_balance = 0;

    return 0;
}

static std::vector<Deposit> get_deposits_from_transaction(std::string decoded_string) {
    std::vector<Deposit> deposits;
    return deposits;
}

static void fill_inputs(std::vector<unsigned long long> deposit_ids,
                 std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
                 std::string& inputs,
                 unsigned int index_to_start_at) {

    for (unsigned int i = 0; i < deposit_ids.size(); i++) {
        unsigned long long deposit_id = deposit_ids[i];
        Deposit deposit = deposit_ids_to_deposits[deposit_id];

        std::string txid = deposit.txid;
        unsigned long long tx_index = deposit.tx_index;

        if ((index_to_start_at != 0) || (i != 0)) {
            inputs += ","; // add commas if not first item
        }

        inputs += "{\"txid\":\"" + txid + "\",\"vout\":" + TOSTR(tx_index) + "}";
    }
}

void fill_private_keys(std::vector<unsigned long long> deposit_ids,
                                   std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
                                   std::string& private_keys,
                                   unsigned int index_to_start_at) {

    for (unsigned int i = 0; i < deposit_ids.size(); i++) {
        unsigned long long deposit_id = deposit_ids[i];
        Deposit deposit = deposit_ids_to_deposits[deposit_id];

        if ((index_to_start_at != 0) || (i != 0)) {
            private_keys += ","; // add commas if not first item
        }

        private_keys += "\"" + deposit.private_key + "\"";
    }
}

static void fill_prevouts(std::vector<unsigned long long> deposit_ids,
                     std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
                     std::string& prevouts,
                     unsigned int index_to_start_at) {

    for (unsigned int i = 0; i < deposit_ids.size(); i++) {
        unsigned long long deposit_id = deposit_ids[i];
        Deposit deposit = deposit_ids_to_deposits[deposit_id];
        unsigned long long tx_index = deposit.tx_index;
        std::string txid = deposit.txid;

        if ((index_to_start_at != 0) || (i != 0)) {
            prevouts += ","; // add commas if not first item
        }

        prevouts += "{\"txid\":\"" + txid + "\",\"vout\":" + TOSTR(tx_index) + ",\"scriptPubKey\":\"" + deposit.script + "\",\"redeemScript\":\"\"}";
    }
}

static std::string get_all_prevouts_for_unused_deposits(
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::vector<unsigned long long> unused_deposits) {
    std::string prevouts = "[";

    fill_prevouts(unused_deposits, deposit_ids_to_deposits, prevouts, 0);

    prevouts += "]"; // close prevout list
    return prevouts;
}

static std::string get_all_private_keys_for_unused_deposits(
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::vector<unsigned long long> unused_deposits) {
    std::string private_keys = "["; // open private key list

    // fill my private keys for channel
    fill_private_keys(unused_deposits, deposit_ids_to_deposits, private_keys, 0);

    private_keys += "]"; // close private key list
    return private_keys;
}

static std::string get_all_prevouts_for_deposits(std::string channel_id,
        std::map<unsigned long long, std::string> deposit_ids_to_channels,
        std::map<unsigned long long, std::string> remote_deposit_ids_to_channels,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::map<unsigned long long, Deposit> remote_deposit_ids_to_deposits) {
    std::string prevouts = "[";

    // fill my prevouts for channel
    std::vector<unsigned long long> my_deposit_ids = find_deposit_ids_in_channel(channel_id, deposit_ids_to_channels);
    fill_prevouts(my_deposit_ids, deposit_ids_to_deposits, prevouts, 0);

    // fill remote prevouts for channel
    std::vector<unsigned long long> remote_deposit_ids = find_deposit_ids_in_channel(channel_id, remote_deposit_ids_to_channels);
    fill_prevouts(remote_deposit_ids, remote_deposit_ids_to_deposits, prevouts, my_deposit_ids.size());

    prevouts += "]"; // close prevout list
    return prevouts;
}

std::string get_all_private_keys_for_deposits(std::string channel_id,
        std::map<unsigned long long, std::string> deposit_ids_to_channels,
        std::map<unsigned long long, std::string> remote_deposit_ids_to_channels,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::map<unsigned long long, Deposit> remote_deposit_ids_to_deposits) {

    std::string private_keys = "["; // open private key list

    // fill my private keys for channel
    std::vector<unsigned long long> my_deposit_ids = find_deposit_ids_in_channel(channel_id, deposit_ids_to_channels);
    fill_private_keys(my_deposit_ids, deposit_ids_to_deposits, private_keys, 0);

    // fill remote private keys for channel
    std::vector<unsigned long long> remote_deposit_ids = find_deposit_ids_in_channel(channel_id, remote_deposit_ids_to_channels);
    fill_private_keys(remote_deposit_ids, remote_deposit_ids_to_deposits, private_keys, my_deposit_ids.size());

    private_keys += "]"; // close private key list
    return private_keys;
}

static std::string sign_settle_transaction_for_channel(std::string channel_id, std::string settle_transaction_hash,
        std::map<unsigned long long, std::string> deposit_ids_to_channels,
        std::map<unsigned long long, std::string> remote_deposit_ids_to_channels,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::map<unsigned long long, Deposit> remote_deposit_ids_to_deposits) {

    std::string prevouts = get_all_prevouts_for_deposits(channel_id, deposit_ids_to_channels,
            remote_deposit_ids_to_channels, deposit_ids_to_deposits, remote_deposit_ids_to_deposits);
    std::string privkeys = get_all_private_keys_for_deposits(channel_id, deposit_ids_to_channels,
            remote_deposit_ids_to_channels, deposit_ids_to_deposits, remote_deposit_ids_to_deposits);

    std::string sign_transaction_rpc = sign_raw_transaction_rpc();
    sign_transaction_rpc += settle_transaction_hash + " " + prevouts + " " + privkeys + " ALL";

    printf("Entire Command to execute: %s", sign_transaction_rpc.c_str());
    UniValue signed_settle_transaction = executeCommand(sign_transaction_rpc);
    std::string signed_settle_transaction_string = remove_surrounding_quotes(signed_settle_transaction["hex"].write());

    return signed_settle_transaction_string;
}

static void append_output_to_settlement_transaction(std::string* output_string, std::string my_address,
            std::string remote_address, unsigned long long my_balance, unsigned long long remote_balance, unsigned long long miner_fee_to_pay) {
    signed long long to_pay = my_balance - miner_fee_to_pay;

    if (my_address == remote_address) {
        // Write only a single output
        signed long long total_out = to_pay + remote_balance;
        if (total_out > 0) {
            *output_string += "\"" + my_address + "\":" + satoshi_to_bitcoin(total_out);
        }
    } else {
        // Write the two outputs based on the balances
        if (to_pay > 0 && remote_balance > 0) {
          *output_string += "\"" + my_address + "\":" + satoshi_to_bitcoin(to_pay);
          *output_string += ",\"" + remote_address + "\":" + satoshi_to_bitcoin(remote_balance);
        } else {
            if (to_pay > 0) {
                *output_string += "\"" + my_address + "\":" + satoshi_to_bitcoin(to_pay);
            }
            if (remote_balance > 0) {
                *output_string += "\"" + remote_address + "\":" + satoshi_to_bitcoin(remote_balance);
            }
        }
    }
}

static std::string create_settle_transaction_for_channel(
        std::string channel_id,
        std::map<unsigned long long, std::string> my_deposit_ids_to_channels,
        std::map<unsigned long long, std::string> remote_deposit_ids_to_channels,
        std::map<unsigned long long, Deposit> my_deposit_ids_to_deposits,
        std::map<unsigned long long, Deposit> remote_deposit_ids_to_deposits,
        unsigned long long my_balance,
        unsigned long long remote_balance,
        unsigned long long miner_fee,
        std::string my_address,
        std::string remote_address) {

    std::string input_string = "["; // open list of inputs
    std::string output_string = "{"; // open outputs

    // fill my inputs
    std::vector<unsigned long long> my_deposit_ids = find_deposit_ids_in_channel(channel_id, my_deposit_ids_to_channels);
    fill_inputs(my_deposit_ids, my_deposit_ids_to_deposits, input_string, 0 /* index to start at */);

    // fill remote inputs
    std::vector<unsigned long long> remote_deposits = find_deposit_ids_in_channel(channel_id, remote_deposit_ids_to_channels);
    fill_inputs(remote_deposits, remote_deposit_ids_to_deposits, input_string, my_deposit_ids.size());

    // Calculate miner fee using the given miner fee per byte value
    miner_fee = calculate_total_fee(miner_fee, my_deposit_ids.size() + remote_deposits.size(), 2);

    // We pay the miner fee because we want to generate the transaction!
    if (my_balance <= miner_fee) {
        printf("Warning! The amount of money you have remaining in the channel "
               "is less than the miner fee to pay! We are generating a transaction for you, "
               "but it won't have a miner fee!");
        append_output_to_settlement_transaction(&output_string, my_address, remote_address, my_balance, remote_balance, 0);
    } else {
        append_output_to_settlement_transaction(&output_string, my_address, remote_address, my_balance, remote_balance, miner_fee);
    }

    input_string += "]"; // close list of inputs
    output_string += "}"; // close outputs

    std::string create_transaction_rpc = create_raw_transaction_rpc();
    create_transaction_rpc += input_string + " " + output_string;
    UniValue settle_transaction = executeCommand(create_transaction_rpc);
    std::string settle_transaction_string = remove_surrounding_quotes(settle_transaction.write());
    return settle_transaction_string;
}

static BackupChannelStateMsg find_channel_backup_state_for(std::string given_channel_id) {
    BackupChannelStateMsg channel_state_found;

    for (unsigned int i = 0; i < most_recent_backup_state.num_channels; i++) {
        BackupChannelStateMsg channel_state = most_recent_backup_state.channel_states[i];
        std::string channel_id(channel_state.channel_id, CHANNEL_ID_LEN);
        if (channel_id == given_channel_id) {
            channel_state_found = channel_state;
        }
    }

   return channel_state_found;
}

static std::string generate_settle_transaction_for_channel(std::string channel_id) {
    // The following differ if on primary or backup
    std::map<unsigned long long, std::string> deposit_ids_to_channels;
    std::map<unsigned long long, std::string> remote_deposit_ids_to_channels;
    std::map<unsigned long long, Deposit> deposit_ids_to_deposits;
    std::map<unsigned long long, Deposit> remote_deposit_ids_to_deposits;
    unsigned long long my_balance;
    unsigned long long remote_balance;
    std::string my_address;
    std::string remote_address;
    unsigned long long miner_fee;

    if (check_state(Backup)) {
        BackupSetupTransactionStateMsg setup_transaction = most_recent_backup_state.my_setup_transaction;
        BackupChannelStateMsg channel_backup = find_channel_backup_state_for(channel_id);

        // fill my fields
        deposit_ids_to_channels = extract_deposit_channel_mapping_from_backup(false);
        deposit_ids_to_deposits = extract_deposit_mapping_from_backup();
        my_address = std::string(channel_backup.bitcoin_address_a, BITCOIN_ADDRESS_LEN);

        // fill remote fields
        remote_deposit_ids_to_channels = extract_deposit_channel_mapping_from_backup(true);
        remote_deposit_ids_to_deposits = extract_remote_deposit_mapping_from_backup();
        remote_address = std::string(channel_backup.bitcoin_address_b, BITCOIN_ADDRESS_LEN);

        // fill balances
        my_balance = channel_backup.balance_a;
        remote_balance = channel_backup.balance_b;
        miner_fee = setup_transaction.miner_fee;

    } else { // Primary
        ChannelState* state = get_channel_state(channel_id);

        deposit_ids_to_channels = my_setup_transaction.deposit_ids_to_channels;
        remote_deposit_ids_to_channels = state->remote_setup_transaction.deposit_ids_to_channels;
        deposit_ids_to_deposits = my_setup_transaction.deposit_ids_to_deposits;
        remote_deposit_ids_to_deposits = state->remote_setup_transaction.deposit_ids_to_deposits;
        my_balance = state->my_balance;
        remote_balance = state->remote_balance;
        my_address = my_setup_transaction.my_address;
        remote_address = state->remote_setup_transaction.my_address;
        miner_fee = my_setup_transaction.miner_fee;
    }

    std::string generated_transaction = create_settle_transaction_for_channel(channel_id, deposit_ids_to_channels,
            remote_deposit_ids_to_channels, deposit_ids_to_deposits, remote_deposit_ids_to_deposits, my_balance,
            remote_balance, miner_fee, my_address, remote_address);

    return sign_settle_transaction_for_channel(channel_id, generated_transaction, deposit_ids_to_channels,
            remote_deposit_ids_to_channels, deposit_ids_to_deposits, remote_deposit_ids_to_deposits);
}

static std::string sign_return_transaction_for_unused_deposits(std::string return_transaction,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits,
        std::vector<unsigned long long> unused_deposits) {
    std::string prevouts = get_all_prevouts_for_unused_deposits(deposit_ids_to_deposits, unused_deposits);
    std::string privkeys = get_all_private_keys_for_unused_deposits(deposit_ids_to_deposits, unused_deposits);

    std::string sign_transaction_rpc = sign_raw_transaction_rpc();
    sign_transaction_rpc += return_transaction + " " + prevouts + " " + privkeys + " ALL";

    //printf("Entire Command to execute: %s", sign_transaction_rpc.c_str());
    UniValue signed_return_transaction = executeCommand(sign_transaction_rpc);
    std::string signed_return_transaction_string = remove_surrounding_quotes(signed_return_transaction["hex"].write());

    return signed_return_transaction_string;
}

static std::string create_return_transaction_for_unused_deposits(std::string my_address,
        unsigned long long miner_fee, std::vector<unsigned long long> unused_deposit_ids,
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits) {

    std::string input_string = "["; // open list of inputs
    std::string output_string = "{"; // open outputs

    // Fill inputs
    fill_inputs(unused_deposit_ids, deposit_ids_to_deposits, input_string, 0 /* index to start at */);

    // Calculate miner fee using the given miner fee per byte value
    miner_fee = calculate_total_fee(miner_fee, unused_deposit_ids.size(), 1);

    // Write the output based on the sum of the deposit balances and handle miner fees
    unsigned long long unused_deposit_amount = sum_unused_deposits(deposit_ids_to_deposits, unused_deposit_ids);
    unsigned long long amount_to_return;

    if (unused_deposit_amount <= miner_fee) {
        printf("Warning! The amount of money you have remaining in unused deposits "
               "is less than the miner fee to pay! We are generating a transaction for you, "
               "but it won't have a miner fee!");
        amount_to_return = unused_deposit_amount;
    } else {
        amount_to_return = unused_deposit_amount - miner_fee;
    }

    output_string += "\"" + my_address + "\":" + satoshi_to_bitcoin(amount_to_return);

    input_string += "]"; // close list of inputs
    output_string += "}"; // close outputs

    std::string create_transaction_rpc = create_raw_transaction_rpc();
    create_transaction_rpc += input_string + " " + output_string;
    UniValue return_transaction = executeCommand(create_transaction_rpc);
    std::string return_transaction_string = remove_surrounding_quotes(return_transaction.write());
    return return_transaction_string;
}

static bool settle(std::string given_channel_id, std::string& output) {
    std::string generated_settle_transaction;

    if (!check_state(Backup)) {  // Primary
        ChannelState* state = get_channel_state(given_channel_id);
       	generated_settle_transaction = generate_settle_transaction_for_channel(given_channel_id);
        state->status = Settled;
    } else {  // Backup
        generated_settle_transaction = generate_settle_transaction_for_channel(given_channel_id);
    }

    // TODO: send notification of settlement to remote host, so they know too.

    output += "This transaction has settled your channel: " + given_channel_id + ", please broadcast it to the Bitcoin network!\n";
    output += generated_settle_transaction + "\n";
    return true;
}

// Can only be called by primary
int ecall_settle(const char *channel_id, int channel_len, char* user_output) {
    if (!check_state(Funded)) {
	printf("Cannot settle channel; this enclave is not funded!");
        return REQUEST_FAILED;
    }

    std::string given_channel_id(channel_id, channel_len);
    ChannelState* state = get_channel_state(given_channel_id);
    //log_debug("ecall_settle: %s", given_channel_id.c_str());

    if (!check_status(state, Alive) && !check_status(state, Settled)) {
	printf("Cannot settle channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    std::string output;
    if (!settle(given_channel_id, output)) {
	printf("Settle failed!");
        return REQUEST_FAILED;
    }
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

static void mark_unused_deposits_spent(std::vector<unsigned long long> unused_deposit_ids) {
    for (unsigned int i = 0; i < unused_deposit_ids.size(); i++) {
        unsigned long long deposit_id = unused_deposit_ids[i];
        Deposit* deposit = &(my_setup_transaction.deposit_ids_to_deposits[deposit_id]);
        deposit->is_spent = true;
    }
}

static bool return_deposits(std::string& output) {
    // The following are calculated differently based on if primary or if backup node
    std::string my_address;
    unsigned long long miner_fee;
    std::map<unsigned long long, Deposit> deposit_ids_to_deposits;
    std::vector<unsigned long long> unused_deposit_ids;

    if (check_state(Backup)) {
        BackupSetupTransactionStateMsg setup_transaction = most_recent_backup_state.my_setup_transaction;

        my_address = std::string(setup_transaction.my_address, BITCOIN_ADDRESS_LEN);
        miner_fee = setup_transaction.miner_fee;

        deposit_ids_to_deposits = extract_deposit_mapping_from_backup();
        unused_deposit_ids = find_unused_deposits(deposit_ids_to_deposits,
                extract_deposit_channel_mapping_from_backup(false));

    } else { // Primary
        my_address = my_setup_transaction.my_address;
        miner_fee = my_setup_transaction.miner_fee;
        deposit_ids_to_deposits = my_setup_transaction.deposit_ids_to_deposits;
        unused_deposit_ids = find_unused_deposits(deposit_ids_to_deposits,
                my_setup_transaction.deposit_ids_to_channels);
    }

    // check there are unused deposit indexes
    if (unused_deposit_ids.size() == 0) {
        printf("No unused deposits to return!\n");
        return false;
    }

    std::string generated_transaction = create_return_transaction_for_unused_deposits(my_address, miner_fee,
            unused_deposit_ids, deposit_ids_to_deposits);
    std::string signed_return_transaction = sign_return_transaction_for_unused_deposits(generated_transaction,
            deposit_ids_to_deposits, unused_deposit_ids);

    if (!check_state(Backup)) {
        mark_unused_deposits_spent(unused_deposit_ids);
    }

    // print transaction
    output += "This transaction has returned your unused deposits!\n";
    output += signed_return_transaction + "\n";
    return true; 
}

// Can only be called by primary
int ecall_return_deposits(char* user_output) {
    std::string output;

    if (!check_state(Funded)) {
	printf("Cannot return unused deposits; this enclave is not funded!\n");
    	memcpy(user_output, output.c_str(), output.length() + 1);
        return REQUEST_FAILED;
    }

    if (!return_deposits(output)) {
	printf("Return deposits failed!");
    	memcpy(user_output, output.c_str(), output.length() + 1);
        return REQUEST_FAILED;
    }

    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

static std::vector<std::string> get_channel_ids_from_backup() {
    std::vector<std::string> channels;

    for (unsigned int i = 0; i < most_recent_backup_state.num_channels; i++) {
        BackupChannelStateMsg channel_state = most_recent_backup_state.channel_states[i];
        std::string channel_id(channel_state.channel_id, CHANNEL_ID_LEN);
        channels.push_back(channel_id);
    }

    return channels;
}


// Can be called by primary or backups
int ecall_shutdown(char* user_output) {
    std::string output;
    if (!check_state(Backup) && !check_state(Funded)) {
        printf("Cannot shutdown enclave channels or returned unused deposits; not in the correct state!");
        return REQUEST_FAILED;
    	memcpy(user_output, output.c_str(), output.length() + 1);
    }

    // return deposits
    if (!return_deposits(output)) {
	printf("Return deposits failed!");
    }

    // settle all channels
    std::vector<std::string> channel_ids;
    if (check_state(Backup)) {
        channel_ids = get_channel_ids_from_backup();
    } else {
        channel_ids = get_all_non_backup_channel_ids();
    }
    for (unsigned int i = 0; i < channel_ids.size(); i++) {
        std::string channel_id = channel_ids[i];

        unsigned long long my_balance;
        unsigned long long remote_balance;
        if (check_state(Backup)) {
            BackupSetupTransactionStateMsg setup_transaction = most_recent_backup_state.my_setup_transaction;
            BackupChannelStateMsg channel_backup = find_channel_backup_state_for(channel_id);

            my_balance = channel_backup.balance_a;
            remote_balance = channel_backup.balance_b;
        } else { // Primary
            ChannelState* state = get_channel_state(channel_id);

            my_balance = state->my_balance;
            remote_balance = state->remote_balance;
        }

        if (my_balance == 0 && remote_balance == 0) {
            break;  // The channel might be empty (don't try and generate a tx!)
        }

        if (!settle(channel_id, output)) {
	    printf("Settle failed!");
    	    memcpy(user_output, output.c_str(), output.length() + 1);
            return REQUEST_FAILED;
        }
    }

    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

bool check_and_decrypt_message(const char* blob, int blob_len, sgx_ra_context_t context, int msg_len, unsigned char* msg)  {
    if (blob_len <= SAMPLE_SP_TAG_SIZE) {
        printf("bad input: blob_len must be at least the size of a mac + data, but got: ", blob_len);
        return false;
    }

    int mac_and_msg_len = SAMPLE_SP_TAG_SIZE + msg_len;

    if (blob_len < mac_and_msg_len) {
        printf("incomplete message and mac");
        return false;
    }

    // separate mac and message data
    unsigned char* mac = (unsigned char*) blob;
    unsigned char* msg_data = (unsigned char*) (blob + SAMPLE_SP_TAG_SIZE);

    // decrypt message
    if ((sgx_decrypt(msg_data, msg_len, mac, context, msg) != 0)) {
        printf("bad sgx_decrypt request");
        return false;
    }
    
    return true;
}

int ecall_debug_enclave() {
    debug = true;
    return 0;
}

int ecall_benchmark_enclave() {
    benchmark = true;
    return 0;
}

int ecall_primary(bool use_monotonic_counters, char* user_output) {
    if (!check_state(Ghost)) {
        printf("Cannot assign this node as primary; not in the correct state!");
        return 1;
    }
    teechain_state = Primary;
    write_to_stable_storage = use_monotonic_counters;

    std::string output = "Your Enclave has been made into a Primary Teechain node!\n";
    output += "To use it, please fund your enclave by setting up your funding deposits!\n";
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

int ecall_remote_verify_deposits(const char *channel_id, int channel_len) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState *state = get_channel_state(channel_id_s);

    if (!check_status(state, Unverified)) {
        printf("Cannot verify deposits for channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }
    
    state->other_party_deposits_verified = true;

    if (state->deposits_verified) {
        state->status = Alive;
    }

    return 0;
}

int ecall_verify_deposits(const char *channel_id, int channel_len, char* user_output) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState *state = get_channel_state(channel_id_s);

    if (!check_status(state, Unverified)) {
	printf("Cannot verify deposits for channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    state->deposits_verified = true;

    if (state->other_party_deposits_verified) {
        state->status = Alive;
    }

    std::string output = "You have verified the funding transaction of the remote party in channel: " + channel_id_s + ".\n";
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

int ecall_get_user_output(const char *channel_id, int channel_len, char* user_output) {
    std::string channel_id_s(channel_id, channel_len);

    std::string output = channel_ids_to_user_outputs[channel_id_s];
    // Should return an empty string if fails

    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

int ecall_balance(const char *channel_id, int channel_len, char* user_output) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState *state = get_channel_state(channel_id_s);

    if (!check_status(state, Alive)) {
	printf("Cannot display balance for channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    // Print deposits in channel, and balances
    std::vector<unsigned long long> deposit_ids_in_channel =
            find_deposit_ids_in_channel(channel_id_s, my_setup_transaction.deposit_ids_to_channels);

    std::string output = "Printing balance and deposits for channel: " + channel_id_s + ".\n";

    unsigned int num_deposits = deposit_ids_in_channel.size();
    if (num_deposits == 0) {
        output += "You have no deposits in this channel.\n";
    } else {
        output += "You have " + TOSTR(num_deposits) + " deposits in this channel.\n";
        for (unsigned int i = 0; i < deposit_ids_in_channel.size(); i++) {
            unsigned int deposit_id = deposit_ids_in_channel[i];
            Deposit deposit = my_setup_transaction.deposit_ids_to_deposits[deposit_id];
            output += "Deposit index: " + TOSTR(deposit_id) + ", amount: " + TOSTR(deposit.deposit_amount) + " (satoshi).\n";
        }
    }
    output += "My balance is: " + TOSTR(state->my_balance) + ", remote balance is: " + TOSTR(state->remote_balance) + " (satoshi).\n";

    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0;
}

int ecall_send_bitcoins(const char *channel_id, int channel_len, unsigned long long amount, char* encrypted_send_request, int *len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action) {
    std::string given_channel_id(channel_id, channel_len);
    ChannelState* state = get_channel_state(given_channel_id);

    if (!check_status(state, Alive)) {
	printf("Cannot send on channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    // ensure that we have the funds
    if (amount <= 0 || amount > state->my_balance) {
        printf("Cannot send amount %d, balance is %d", amount, state->my_balance);
        return REQUEST_FAILED; // don't error, just return
    }

    // sending a bitcoin payment:
    // update internal balances and state
    state->my_balance -= amount;
    state->remote_balance += amount;

    // write user output
    if (write_to_stable_storage) {
        log_debug("We need to increment our monotonic counters and then send the payment!");
        increment_monotonic_counter_and_write_state_to_storage(given_channel_id);
        return send_bitcoin_payment_message(given_channel_id, amount, encrypted_send_request, len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    if (have_backup()) {
        log_debug("We have backups! Need to wait for them to update first!");
        std::string channel_id_blocked_on = given_channel_id;
        std::string nonce = generate_random_nonce();

        struct BackupRequest backup_request;
        backup_request.request_blocked_on = Send_Bitcoin_Request;
        backup_request.send_amount_blocked_on = amount;
        memcpy(backup_request.nonce, nonce.c_str(), NONCE_BYTE_LEN);

        ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
        backup_state->backup_requests[nonce] = backup_request;

        return send_update_channel_balance_request(channel_id_blocked_on, nonce, false, encrypted_send_request, len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    } else {
        log_debug("We have no backups! Sending payment message!");
        return send_bitcoin_payment_message(given_channel_id, amount, encrypted_send_request, len, p_gcm_mac, next_channel_id_to_send_on, send_action);

    }
        
    return REQUEST_CRASHED; // should never happen 
}

int ecall_receive_bitcoins(const char *channel_id, int channel_len, const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char *next_channel_id_to_send_on, int* send_action, char* user_output) {
    std::string given_channel_id(channel_id, channel_len);
    ChannelState* state = get_channel_state(given_channel_id);

    if (!check_deposits_verified(state)) {
        printf("Channel is not established by both parties! Cannot send bitcoins!");
        return 1;
    }

    struct SendMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct SendMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    if (msg.monotoniccount <= state->remote_last_seen) {
        printf("replayed request: we have seen later messages");
        return 1; 
    }

    // authenticated payment, accept the funds
    state->remote_last_seen = msg.monotoniccount;
    state->my_balance += msg.amount;
    state->remote_balance -= msg.amount;
    state->my_receives++;

    state->unsynced_bitcoin_amount += msg.amount;

    // write user output
    std::string output = "Received " + TOSTR(msg.amount) + " satoshi on channel: " + given_channel_id + ".\n";
    output += "My balance is now: " + TOSTR(state->my_balance) + ", remote balance is: " + TOSTR(state->remote_balance) + " (satoshi).\n";
    memcpy(user_output, output.c_str(), output.length() + 1);

    if (state->unsynced_bitcoin_amount > MAX_AMOUNT_TO_RECEIVE_BEFORE_SYNC) {

        if (write_to_stable_storage) {
            //log_debug("We have received more than we are willing to lose! We need to synchronize!");
            log_debug("Incrementing our monotonic counter and saving state before acking the payment!");
            increment_monotonic_counter_and_write_state_to_storage(given_channel_id);
            return send_receive_ack(given_channel_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
        }

        if (have_backup()) {
            //log_debug("We have received more than we are willing to lose! We need to synchronize!");
            log_debug("Waiting for our backup to store our state before giving the payment ack!");
            std::string channel_id_blocked_on = given_channel_id;
            std::string nonce = generate_random_nonce();

            struct BackupRequest backup_request;
            backup_request.request_blocked_on = Receive_Bitcoin_Request;
            backup_request.send_amount_blocked_on = msg.amount;
            memcpy(backup_request.nonce, nonce.c_str(), NONCE_BYTE_LEN);

            ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
            backup_state->backup_requests[nonce] = backup_request;

            return send_update_channel_balance_request(channel_id_blocked_on, nonce, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
        }

    }

    // no need to backup
    log_debug("We have received an incoming payment!");
    return send_receive_ack(given_channel_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

// pad string to a multiple of 16 bytes
std::string pad_string_to_multiple_16(std::string str) {
    if (((str.length() + 1) % 16) != 0) {
        std::string padding("                ");
        str += padding.substr(0, 16 - ((str.length()+1) % 16));
    }
    return str;
}

bool check_message_nonce(ChannelState* channel, char* message_nonce) {
    std::string nonce(message_nonce, NONCE_BYTE_LEN);
    if (channel->most_recent_nonce != nonce) {
        printf("Invalid message nonce! Current: %s, Given: %s", channel->most_recent_nonce.c_str(), nonce.c_str());
        printf("Length of current: %d, length of given: %d", channel->most_recent_nonce.length(), nonce.length());
        return false;
    }

    return true;
}

int ecall_verify_deposit_removed_from_channel(const char *data, int data_len, sgx_ra_context_t context, char* user_output) {
    // TODO: state check

    struct SecureAckMsg msg;
    if (!check_and_decrypt_message(data, data_len, context, sizeof(struct SecureAckMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    ChannelState* state = get_channel_state(channel_id);

    // check secure ack and nonce
    if (!check_message_nonce(state, msg.nonce)) {
        return 1;
    }

    if (msg.result != REMOVE_DEPOSIT_ACK) {
        printf("ecall_verify_deposit_remove from_channel: invalid ack response");
        return 1;
    }

    std::string output = channel_ids_to_user_outputs[channel_id];
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0; 
}

int ecall_verify_deposit_added_to_channel(const char *data, int data_len, sgx_ra_context_t context, char* user_output) {
    // TODO: state check

    struct SecureAckMsg msg;
    if (!check_and_decrypt_message(data, data_len, context, sizeof(struct SecureAckMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    ChannelState* state = get_channel_state(channel_id);

    // check secure ack and nonce
    if (!check_message_nonce(state, msg.nonce)) {
        return 1;
    }

    if (msg.result != ADD_DEPOSIT_ACK) {
        printf("ecall_verify_deposit_added_to_channel: invalid ack response");
        return 1;
    }

    std::string output = channel_ids_to_user_outputs[channel_id];
    memcpy(user_output, output.c_str(), output.length() + 1);
    return 0; 
}

int ecall_remove_remote_deposit_from_channel(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char* next_channel_id_to_send_on, int* send_action) {

    struct DepositMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct DepositMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    // parse given remove deposit message
    if (msg.deposit_operation != REMOVE_DEPOSIT) {
        printf("invalid deposit operation!");
        return 1;
    }
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    std::string given_channel_id(msg.channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id_to_remove = msg.deposit_id;

    ChannelState* state = get_channel_state(given_channel_id);

    // check valid deposit_index
    if (deposit_id_to_remove >= state->remote_setup_transaction.deposit_ids_to_deposits.size()) {
        printf("invalid deposit_id");
        return 1; 
    }

    // check deposit index matches the given channel
    std::map<unsigned long long, std::string>::iterator it;
    it = state->remote_setup_transaction.deposit_ids_to_channels.find(deposit_id_to_remove);
    if (it->second != given_channel_id) {
        printf("deposit removal failed: channel is incorrect!");
        return 1;
    }

    // remove deposit from the channel and update balance
    remove_deposit_from_channel(deposit_id_to_remove, &(state->remote_setup_transaction.deposit_ids_to_channels));
    state->remote_balance -= state->remote_setup_transaction.deposit_ids_to_deposits[deposit_id_to_remove].deposit_amount;

    if (write_to_stable_storage) {
        printf("We need to increment our monotonic counters before acking the deposit was removed!");
        increment_monotonic_counter_and_write_state_to_storage(given_channel_id);
        return send_remove_deposit_ack(given_channel_id, given_nonce, deposit_id_to_remove, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    if (!have_backup()) { // I have no backups
        printf("I don't have any backups! Sending remove deposit ack!");
        return send_remove_deposit_ack(given_channel_id, given_nonce, deposit_id_to_remove, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    printf("Waiting for my backups to ack this new deposit to remove!");
    std::string channel_id_blocked_on = given_channel_id;
    std::string nonce(msg.nonce, NONCE_BYTE_LEN);

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Remove_Deposit_Ack;
    backup_request.deposit_id_blocked_on = deposit_id_to_remove;
    memcpy(backup_request.nonce, msg.nonce, NONCE_BYTE_LEN);

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_backup_store_request(channel_id_blocked_on, backup_request, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

int ecall_add_remote_deposit_to_channel(const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char* next_channel_id_to_send_on, int* send_action) {

    struct DepositMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct DepositMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    // parse given add deposit message
    if (msg.deposit_operation != ADD_DEPOSIT) {
        printf("invalid deposit operation!");
        return REQUEST_CRASHED; // someone tampered with the message op? die...
    }
    std::string given_nonce(msg.nonce, NONCE_BYTE_LEN);
    std::string given_channel_id(msg.channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id_to_add = msg.deposit_id;

    ChannelState* state = get_channel_state(given_channel_id);

    // check valid deposit_id
    if (deposit_id_to_add >= state->remote_setup_transaction.deposit_ids_to_deposits.size()) {
        printf("invalid deposit_id");
        return REQUEST_FAILED; 
    }

    // assign deposit to the channel and update balances
    state->remote_setup_transaction.deposit_ids_to_channels[deposit_id_to_add] = given_channel_id;
    state->remote_balance += state->remote_setup_transaction.deposit_ids_to_deposits[deposit_id_to_add].deposit_amount;

    if (write_to_stable_storage) {
        printf("We need to increment our monotonic counters before acking the deposit was removed!");
        increment_monotonic_counter_and_write_state_to_storage(given_channel_id);
        return send_add_deposit_ack(given_channel_id, given_nonce, deposit_id_to_add, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    if (!have_backup()) { // I have no backups
        printf("I don't have any backups! Sending remove deposit ack!");
        return send_add_deposit_ack(given_channel_id, given_nonce, deposit_id_to_add, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    printf("Waiting for my backups to ack this new deposit to add!");
    std::string channel_id_blocked_on = given_channel_id;
    std::string nonce(msg.nonce, NONCE_BYTE_LEN);

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Add_Deposit_Ack;
    backup_request.deposit_id_blocked_on = deposit_id_to_add;
    memcpy(backup_request.nonce, msg.nonce, NONCE_BYTE_LEN);

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_backup_store_request(channel_id_blocked_on, backup_request, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

int ecall_remove_deposit_from_channel(const char *channel_id, int channel_len, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char* next_channel_id_to_send_on, int* send_action) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState* state = get_channel_state(channel_id_s);

    if (!check_status(state, Alive)) {
	printf("Cannot remove deposit from channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    // check valid deposit_id
    if (deposit_id >= my_setup_transaction.deposit_ids_to_deposits.size()) {
        printf("invalid deposit_id");
        return REQUEST_FAILED; 
    }

    // check deposit index matches the given channel
    std::map<unsigned long long, std::string>::iterator it;
    it = my_setup_transaction.deposit_ids_to_channels.find(deposit_id);
    if (it->second != channel_id_s) {
        printf("deposit removal failed: channel is incorrect!");
        return REQUEST_FAILED;
    }

    // check balances before removing
    unsigned long long amount_to_remove = my_setup_transaction.deposit_ids_to_deposits[deposit_id].deposit_amount;
    if (state->my_balance < amount_to_remove) {
        printf("balance is too low to remove deposit! Balance in channel: %llu, Amount to remove: %llu", state->my_balance, amount_to_remove);
        return REQUEST_FAILED; // don't error -- just return
    }

    // remove deposit from the channel and update balance
    remove_deposit_from_channel(deposit_id, &(my_setup_transaction.deposit_ids_to_channels));
    state->my_balance -= amount_to_remove;

    // write user output
    std::string output = "Removed deposit " + TOSTR(deposit_id) + " from channel " + channel_id_s + ".\n";
    output += "My balance is now: " + TOSTR(state->my_balance) + ", remote balance is: " + TOSTR(state->remote_balance) + " (satoshi).\n";
    channel_ids_to_user_outputs[channel_id_s] = output;

    if (write_to_stable_storage) {
        log_debug("We need to increment our monotonic counters before acking the deposit was removed!");
        increment_monotonic_counter_and_write_state_to_storage(channel_id_s);
        return send_remove_deposit_request(channel_id_s, deposit_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    if (!have_backup()) { // I have no backups
        log_debug("I don't have any backups! Sending remove deposit request!");
        return send_remove_deposit_request(channel_id_s, deposit_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    log_debug("Waiting for my backups to ack this new deposit to remove!");
    std::string channel_id_blocked_on = channel_id_s;
    std::string nonce = generate_random_nonce();

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Remove_Deposit_Request;
    backup_request.deposit_id_blocked_on = deposit_id;
    memcpy(backup_request.nonce, nonce.c_str(), NONCE_BYTE_LEN);

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_backup_store_request(channel_id_blocked_on, backup_request, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

int ecall_add_deposit_to_channel(const char *channel_id, int channel_len, unsigned long long deposit_id, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char* next_channel_id_to_send_on, int* send_action) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState* state = get_channel_state(channel_id_s);

    if (!check_status(state, Alive)) {
	printf("cannot add deposit to channel; channel is not in the correct state!");
        return REQUEST_FAILED;
    }

    // check valid deposit_id
    if (deposit_id >= my_setup_transaction.deposit_ids_to_deposits.size()) {
        printf("invalid deposit_id");
        return REQUEST_FAILED; 
    }

    // check deposit not already spent
    if (is_deposit_spent(deposit_id)) {
        printf("deposit has already been spent!");
        return REQUEST_FAILED;
    }

    // check deposit not already in use
    if (is_deposit_in_use(deposit_id)) {
        printf("deposit already in use!");
        return REQUEST_FAILED;
    }

    // assign deposit to the channel and update balances
    my_setup_transaction.deposit_ids_to_channels[deposit_id] = channel_id_s;
    state->my_balance += my_setup_transaction.deposit_ids_to_deposits[deposit_id].deposit_amount;

    // write user output
    std::string output = "Added deposit " + TOSTR(deposit_id) + " to channel " + channel_id_s + ".\n";
    output += "My balance is now: " + TOSTR(state->my_balance) + ", remote balance is: " + TOSTR(state->remote_balance) + " (satoshi).\n";
    channel_ids_to_user_outputs[channel_id_s] = output;

    if (write_to_stable_storage) {
        log_debug("We need to increment our monotonic counters before acking the deposit was added!");
        increment_monotonic_counter_and_write_state_to_storage(channel_id_s);
        return send_add_deposit_request(channel_id_s, deposit_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    if (!have_backup()) { // I have no backups
        log_debug("I don't have any backups! Sending add deposit request!");
        return send_add_deposit_request(channel_id_s, deposit_id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
    }

    log_debug("Waiting for my backups to ack this new deposit to add!");
    std::string channel_id_blocked_on = channel_id_s;
    std::string nonce = generate_random_nonce();

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Add_Deposit_Request;
    backup_request.deposit_id_blocked_on = deposit_id;
    memcpy(backup_request.nonce, nonce.c_str(), NONCE_BYTE_LEN);

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;

    return send_backup_store_request(channel_id_blocked_on, backup_request, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}

int ecall_get_deposit_data_encrypted(const char *channel_id, int channel_len, char* encrypted_data, int* len, char* p_gcm_mac) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState* state = get_channel_state(channel_id_s);

    // prepare an encrypted message for the remote and give it to untrusted side
    struct CreateChannelMsg msg;
    uint32_t in_len = sizeof(struct CreateChannelMsg);

    // fill message
    memcpy(msg.channel_id, channel_id, CHANNEL_ID_LEN);
    memcpy(msg.bitcoin_address, my_setup_transaction.my_address.c_str(), BITCOIN_ADDRESS_LEN);

    unsigned long long num_deposits = my_setup_transaction.deposit_ids_to_deposits.size();
    msg.num_deposits = num_deposits;
    for (unsigned long long i = 0; i < num_deposits; i++) {
        Deposit deposit = my_setup_transaction.deposit_ids_to_deposits[i];

    
        memcpy((void*) (msg.txids + (i * BITCOIN_TX_HASH_LEN)), deposit.txid.c_str(), BITCOIN_TX_HASH_LEN);
        msg.tx_indexes[i] = deposit.tx_index;
        msg.deposit_amounts[i] = deposit.deposit_amount;

        msg.deposit_script_lengths[i] = deposit.script.length();
        memcpy((void*) (msg.deposit_scripts + (i * MAX_BITCOIN_TX_SCRIPT_LEN)), deposit.script.c_str(), deposit.script.length());

        memcpy((void*) (msg.deposit_bitcoin_addresses + (i * BITCOIN_ADDRESS_LEN)), deposit.bitcoin_address.c_str(), BITCOIN_ADDRESS_LEN);
        memcpy((void*) (msg.deposit_public_keys + (i * BITCOIN_PUBLIC_KEY_LEN)), deposit.public_key.c_str(), BITCOIN_PUBLIC_KEY_LEN);
        memcpy((void*) (msg.deposit_private_keys + (i * BITCOIN_PRIVATE_KEY_LEN)), deposit.private_key.c_str(), BITCOIN_PRIVATE_KEY_LEN);


    }

    // encrypt message
    unsigned char outbuf[in_len];
    unsigned char outmac[SAMPLE_SP_TAG_SIZE];

    if (sgx_encrypt(state, (unsigned char *) &msg, in_len, outbuf, &outmac) != 0) {
        printf("encryption failed, should never happen, shutting down");
        //state->channel_state = Channel_Settled; // deadlock state
        return 1;
    }

    // copy out to untrusted memory
    memcpy(encrypted_data, outbuf, in_len);
    memcpy(p_gcm_mac, outmac, SAMPLE_SP_TAG_SIZE);
    *len = in_len;
    return 0; 
}

int ecall_store_encrypted_deposit_data(const char* channel_id, int channel_len, const char *blob, int blob_len, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, sgx_ra_context_t context, char* next_channel_id_to_send_on, int* send_action) {
    std::string channel_id_s(channel_id, channel_len);
    ChannelState* state = get_channel_state(channel_id_s);

    struct CreateChannelMsg msg;
    if (!check_and_decrypt_message(blob, blob_len, context, sizeof(struct CreateChannelMsg), (unsigned char*) &msg)) {
        return 1; // decryption failed
    }

    // parse given create channel message
    std::string given_channel_id(msg.channel_id, CHANNEL_ID_LEN);
    if (given_channel_id != channel_id_s) {
        printf("Given channel id's don't match!");
        return 1;
    }

    std::string given_bitcoin_address(msg.bitcoin_address, BITCOIN_ADDRESS_LEN);

    std::string output = "A channel has been created!\n";
    output += "Channel ID: " + channel_id_s + "\n";
    output += "The remote has presented their funding deposits. Please verify the following unspent transaction outputs are in the blockchain.\n";
    output += "Number of outputs: " + TOSTR(msg.num_deposits) + ".\n";

    std::map<unsigned long long, Deposit> given_deposit_ids_to_deposits;
    for (unsigned long long i = 0; i < msg.num_deposits; i++) {
        Deposit deposit;
        std::string txid = std::string(msg.txids + (i * BITCOIN_TX_HASH_LEN), BITCOIN_TX_HASH_LEN);
        deposit.txid = txid;
        deposit.tx_index = msg.tx_indexes[i];
        deposit.deposit_amount = msg.deposit_amounts[i];

        deposit.bitcoin_address = std::string(msg.deposit_bitcoin_addresses + (i * BITCOIN_ADDRESS_LEN), BITCOIN_ADDRESS_LEN);
        deposit.public_key = std::string(msg.deposit_public_keys + (i * BITCOIN_PUBLIC_KEY_LEN), BITCOIN_PUBLIC_KEY_LEN);
        deposit.private_key = std::string(msg.deposit_private_keys + (i * BITCOIN_PRIVATE_KEY_LEN), BITCOIN_PRIVATE_KEY_LEN);
        deposit.script = std::string(msg.deposit_scripts + (i * MAX_BITCOIN_TX_SCRIPT_LEN), msg.deposit_script_lengths[i]);

        given_deposit_ids_to_deposits[i] = deposit;

        output += "Transaction ID: " + txid + ", Deposit index " + TOSTR(deposit.tx_index) + " should pay " + TOSTR(deposit.deposit_amount) + " satoshi into address " + deposit.bitcoin_address + ".\n";
    }

    // write user output
    channel_ids_to_user_outputs[given_channel_id] = output;

    // Create enmpty deposit channel map
    std::map<unsigned long long, std::string> given_deposit_ids_to_channels;

    // update channel deposit state and balances
    state->remote_setup_transaction.my_address = given_bitcoin_address;
    state->remote_setup_transaction.deposit_ids_to_deposits = given_deposit_ids_to_deposits;
    state->remote_setup_transaction.deposit_ids_to_channels = given_deposit_ids_to_channels;
    state->remote_balance = 0;

    if (write_to_stable_storage) {
        log_debug("We need to increment our monotonic counters before acking a channel create!");
        increment_monotonic_counter_and_write_state_to_storage(given_channel_id);
        return send_local_ack(given_channel_id, next_channel_id_to_send_on, send_action);
    }

    if (!have_backup()) { // I have no backups -- send ack!
        log_debug("I don't have any backups! Sending local ack as deposit data stored and channel created on my side!");
        return send_local_ack(given_channel_id, next_channel_id_to_send_on, send_action);
    }

    // wait for backup to ack for this request before responding
    log_debug("Waiting for my backups to ack this new channel created state to store!");
    std::string channel_id_blocked_on = given_channel_id;
    std::string nonce = generate_random_nonce();

    struct BackupRequest backup_request;
    backup_request.request_blocked_on = Channel_Create_Request;
    memcpy(backup_request.nonce, nonce.c_str(), NONCE_BYTE_LEN);

    ChannelState* backup_state = get_channel_state(prev_backup_channel_id);
    backup_state->backup_requests[nonce] = backup_request;
    return send_backup_store_request(channel_id_blocked_on, backup_request, false, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, next_channel_id_to_send_on, send_action);
}
