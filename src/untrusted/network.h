#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <string>
#include <vector>

// Constants for networking such as packet headers and op codes
// teechain connection constants
#define DEFAULT_PORT 20202
#define DEFAULT_HOSTNAME "127.0.0.1"
#define MAX_CONNECTIONS 50
#define MAX_BACKLOG 50
#define MAX_EVENTS 10
#define MAXCONN 10000

// Temporary channel handle (this is always overwritten, so it doesn't matter!)
#define TEMPORARY_CHANNEL_ID "0000011111111111111111111111111111111111111111111111111111100000"

// teechain deposit and chain constants
#define MAX_NUM_SETUP_DEPOSITS 10
#define MAX_NUM_CHANNEL_HOPS 10

// local response message codes
#define OP_LOCAL_ACK 1 // ack sent from local enclave to acknowledge received command
#define OP_LOCAL_FAIL 2 // nack sent from local enclave to acknowledge received command

// ghost assignment message codes
#define OP_LOCAL_PRIMARY 10 // send primary assignment to ghost enclave
#define OP_LOCAL_BACKUP 11 // send backup assignment to ghost enclave

// primary setup message codes
#define OP_LOCAL_TEECHAIN_SETUP_DEPOSITS 20 // send local setup deposits to primary
#define OP_LOCAL_TEECHAIN_SETUP 21 // send local setup deposits to primary
#define OP_LOCAL_TEECHAIN_SETUP_TXID 22 // send local setup transaction hash to primary
#define OP_LOCAL_TEECHAIN_DEPOSITS_MADE 23 // send local deposits made message to primary

// primary channel create message codes
#define OP_LOCAL_CREATE 30 // create a channel (local message)
#define OP_REMOTE_CHANNEL_ID_GENERATED 31  // the initiator generated the channel id (remote message) 
#define OP_REMOTE_CHANNEL_CREATE_DATA 32 // create a channel (remote message)
#define OP_LOCAL_VERIFY_DEPOSITS 33 // tell local enclave channel established
#define OP_REMOTE_VERIFY_DEPOSITS_ACK 34 // tell remote channel has been established on remote end

// primary deposit message codes 
#define OP_LOCAL_TEECHAIN_DEPOSIT_ADD 40 // request deposit to be added to channel (local message)
#define OP_LOCAL_TEECHAIN_DEPOSIT_REMOVE 41 // request deposit to be removed from channel (local message)

#define OP_REMOTE_TEECHAIN_DEPOSIT_ADD 42 // request deposit to be added to channel (remote message)
#define OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE 43 // request deposit to be removed from channel (remote message)

#define OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK 44 // deposit added to channel (remote message)
#define OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK 45 // deposit removed from channel (remote message)

// primary send and receive message codes
#define OP_LOCAL_SEND 50 // local send to own enclave
#define OP_REMOTE_SEND 51 // send bitcoin to remote enclave
#define OP_REMOTE_SEND_ACK 52 // send ack to remote enclave that I received bitcoins
#define OP_LOCAL_BALANCE 53 // local get balance on enclave

// backup message codes
#define OP_LOCAL_ADD_BACKUP 70 // local command to add backup
#define OP_REMOTE_BACKUP_DATA 71 // to send encrypted backup data
#define OP_REMOTE_BACKUP_DATA_ACK 72 // to ack remote backup data given and stored

#define OP_LOCAL_REMOVE_BACKUP 73 // local command to remove backup
#define OP_REMOTE_REMOVE_BACKUP 74 // to remove backup from chain
#define OP_REMOTE_REMOVE_BACKUP_ACK 75 // to ack remote removed backup

#define OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA 76 // to send encrypted channel data
#define OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA_ACK 77 // to ack remote channel data given and stored

// shutdown and settle message codes
#define OP_LOCAL_SETTLE 80 // local settle to own enclave
#define OP_LOCAL_SHUTDOWN 81 // local shutdown to own enclave
#define OP_LOCAL_PRESENT_SETTLEMENT 82 // local settle to own enclave, presenting another settlement transaction
#define OP_LOCAL_RETURN_UNUSED 83  // local return unused deposits to own enclave

// remote attestation message codes
#define OP_REMOTE_RA_MSG0 90 // msg0 from non-initiator
#define OP_REMOTE_RA_MSG1 91 // msg1 from non-initiator
#define OP_REMOTE_RA_MSG2 92 // msg2 from non-initiator
#define OP_REMOTE_RA_MSG3 93 // msg3 from non-initiator
#define OP_REMOTE_RA_RESULT 94 // result from non-initiator

// teechain message constants
#define MSG_LEN_BYTES 8 // first eight bytes of message contain message length
#define MSG3_BODY_SIZE 1452
#define SUCC_ATT_MESSAGE_SIZE 8 // the size of the successful attestation message sent during RA
#define MAX_MESSAGE_RESPONSE_LENGTH MAX_ECALL_RETURN_LENGTH

// channel constants
#define CHANNEL_ID_LEN 16
#define REMOTE_HOST_LEN 128

// bitcoin constants
#define BITCOIN_ADDRESS_LEN 34
#define BITCOIN_PUBLIC_KEY_LEN 66
#define BITCOIN_PRIVATE_KEY_LEN 52
#define BITCOIN_TX_HASH_LEN 64
#define MAX_BITCOIN_TX_SCRIPT_LEN 256
#define MAX_BITCOIN_TX_LEN 3000

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

// Function declarations for network API
int connect_to_socket(std::string socket_hostname, int socket_port);
void send_on_socket(char* msg, long msglen, int sockfd);
void read_from_socket(int sockfd, char* buf, long length);

// Network connection state
struct Connection {
  int fd;            // fd here for debugging
  int inuse;         // currently in use or not
  int islocalhost;   // is the remote side localhost
  std::vector<char> input; // the accumulated input so far
};

// Generic Message definition to send messages containing
// blobbed data.
struct LocalGenericMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    char blob[]; // blob of data (e.g. could be encrypted data)
};

// Message structs to define the operations permitted on a teechain
// node.
struct LocalSendMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    unsigned long long amount;
};

struct LocalCreateMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    bool initiator;
    unsigned long long remote_host_len;
    char remote_host[REMOTE_HOST_LEN];
    unsigned long remote_port;
};

struct LocalSetupDepositsMsg {
    char msg_op[1];
    unsigned long long num_deposits;
};

struct LocalSetupMsg {
    char msg_op[1];
    char my_address[BITCOIN_ADDRESS_LEN];
    char setup_public_key[BITCOIN_PUBLIC_KEY_LEN];
    char setup_private_key[BITCOIN_PRIVATE_KEY_LEN];
    char setup_utxo_hash[BITCOIN_TX_HASH_LEN];
    unsigned long long setup_utxo_index;
    char setup_utxo_script[MAX_BITCOIN_TX_SCRIPT_LEN];
    unsigned long long num_deposits;
    unsigned long long deposit_amounts[MAX_NUM_SETUP_DEPOSITS];
};

struct LocalDepositMadeMsg {
    char txid[BITCOIN_TX_HASH_LEN];
    unsigned long long tx_index;
    unsigned long long deposit_amount;
};

struct LocalDepositsMadeMsg {
    char msg_op[1];
    char my_address[BITCOIN_ADDRESS_LEN];
    unsigned long long miner_fee;
    unsigned long long num_deposits;
    struct LocalDepositMadeMsg deposits[MAX_NUM_SETUP_DEPOSITS];
};

struct LocalSetupTxidMsg {
    char msg_op[1];
    char setup_hash[BITCOIN_TX_HASH_LEN];
};

struct LocalDepositMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    unsigned long long deposit_id;
};

struct LocalRouteMsg {
    char msg_op[1];
    unsigned long long amount_to_send;
    unsigned long long num_channel_ids;
    char channel_ids[CHANNEL_ID_LEN * MAX_NUM_CHANNEL_HOPS];
};

struct LocalAssignmentMsg {
    char msg_op[1];
    bool use_monotonic_counters;
};

struct LocalCreateBackupMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    bool initiator;
    unsigned long long remote_host_len;
    char remote_host[REMOTE_HOST_LEN];
    unsigned long remote_port;
};

struct LocalRemoveBackupMsg {
    char msg_op[1];
    char backup_channel_id[CHANNEL_ID_LEN];
};

struct LocalPresentSettlementMsg {
    char msg_op[1];
    char channel_id[CHANNEL_ID_LEN];
    char settlement_transaction[MAX_BITCOIN_TX_LEN];
    unsigned long settlement_transaction_len;
};


#endif /* !_NETWORK_H_ */
