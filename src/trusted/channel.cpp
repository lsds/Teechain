#include "sgx_tkey_exchange.h"

#include "channel.h"
#include "utils.h"

std::map<std::string, ChannelState*> channelStates; // map channel ID to state

void init_channel_state(ChannelState* state) {
    state->status =  Unverified;

    state->remote_last_seen = 0;
    state->my_monotonic_counter = 0;
    state->my_sends = 0;
    state->my_receives = 0;

    state->unsynced_bitcoin_amount = 0;

    state->deposits_verified = false;
    state->other_party_deposits_verified = false;
}

ChannelState* create_channel_state() {
    ChannelState *state = new ChannelState;
    init_channel_state(state);
    return state;
}

ChannelState* get_channel_state(std::string channel_id) {
    std::map<std::string, ChannelState*>::iterator it = channelStates.find(channel_id);
    if (it == channelStates.end()) {
        ocall_print("Trusted get_channel_state() could not find channel state for given channel_id");
        ocall_print(channel_id.c_str());
        ocall_print("Printing contents of channel states!");
        for (std::map<std::string, ChannelState*>::const_iterator it = channelStates.begin(); it != channelStates.end(); it++) {
            ocall_print(it->first.c_str());
        }
        ocall_error("Failed to get state!! Terminating...");
    }
    return it->second;
}

void remove_association(std::string channel_id) {
    channelStates.erase(channel_id);
}

ChannelState* associate_channel_state(std::string channel_id, ChannelState* state_to_associate) {
    channelStates[channel_id] = state_to_associate;
	state_to_associate->channel_id = channel_id;
	return state_to_associate;
}

// TODO: Call this function in an appropriate place
void destroy_channel_state(std::string channel_id) {
	ChannelState *state = get_channel_state(channel_id);
	channelStates.erase(channel_id);
	free(state);
}

std::vector<std::string> get_all_non_backup_channel_ids() {
    std::vector<std::string> channel_ids;
    std::map<std::string, ChannelState*>::iterator it;

    for (it = channelStates.begin(); it != channelStates.end(); it++) {
        ChannelState* state = get_channel_state(it->first);
        if (!state->is_backup_channel) {
            channel_ids.push_back(it->first);
        }
    }

    return channel_ids;
}

bool check_status(ChannelState* state, ChannelStatus status) {
    return state->status == status;
}
