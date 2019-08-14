#ifndef _CHANNEL_H_
#define _CHANNEL_H_

#include <string>
#include <map>
#include <set>
#include <vector>
#include <queue>

#include "service_provider.h"
#include "state.h"

enum BackupBlockRequest {
    Channel_Create_Request, // perform backup: a new channel is being created
    Backup_Store_Request, // a new backup channel is being created
    Send_Bitcoin_Request, // perform backup: we want to send bitcoins
    Receive_Bitcoin_Request, // perform backup: we want to receive bitcoins
    Add_Deposit_Request, // perform backup: we want to add deposit
    Add_Deposit_Ack, // perform backup: acking deposit added
    Remove_Deposit_Request, // perform backup: we want to remove deposit
    Remove_Deposit_Ack, // perform backup: acking deposit removed
};

#include "network.h"  // prevent circular deps

enum ChannelStatus {
    Unverified,  // not yet verified by the remote
    Alive,  // alive and ready to rock
    Settled,  // has been settled
};

class ChannelState {
public:
    ChannelStatus status;
    std::string channel_id;
    bool is_initiator;                // am I the initiator?
    bool is_backup_channel;

    bool deposits_verified;
    bool other_party_deposits_verified;

    SetupTransaction remote_setup_transaction;

    // state per in-flight request
    std::string most_recent_nonce;

    // backup requests in flight
    std::map<std::string, struct BackupRequest> backup_requests;

    // account totals and monotonic counters
    unsigned long long my_balance;
    unsigned long long remote_balance;
    unsigned long long remote_last_seen;      // highest seen transaction from the remote side
    unsigned long long my_monotonic_counter;  // the id of the last transaction sent from me to the other side

    // transactions processed, just for debugging and information
    int my_sends;
    int my_receives;

    // cache to sync across backups
    unsigned long long unsynced_bitcoin_amount; // the current amount of funds in this node not backed up

    // service provider shared secret state
    sp_db_item_t g_sp_db;
};

ChannelState *create_channel_state();
ChannelState *get_channel_state(std::string channel_id);
void destroy_channel_state(std::string channel_id);
ChannelState* associate_channel_state(std::string channel_id, ChannelState* state_to_associate);
void remove_association(std::string channel_id);
std::vector<std::string> get_all_non_backup_channel_ids();
bool check_status(ChannelState* state, ChannelStatus status);

#endif
