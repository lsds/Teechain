#ifndef _CHANNEL_STATE_H_
#define _CHANNEL_STATE_H_

#include <vector>
#include <string>
#include <set>
#include <map>

#include <stdlib.h>

#include "network.h"
#include "utils.h"
#include <pthread.h>

#include "sgx_ukey_exchange.h"
#include "service_provider.h"

extern void log_debug(const char *fmt, ...);
extern struct Connection connections[MAXCONN];
extern struct epoll_event event;
extern struct epoll_event events[MAX_EVENTS];

// Teechan connection
struct ChannelConnectionStruct {
	const char remote_host[REMOTE_HOST_LEN];
	size_t remote_host_len;
	int remote_port;

	const char id[CHANNEL_ID_LEN];

	int remote_sockfd; // active communication socket with remote enclave
    int local_sockfd; // any local active communication socket (i.e. if a local command is waiting for an ack)
};
typedef struct ChannelConnectionStruct ChannelConnection;

struct ChannelStateStruct {
	bool is_initiator; // shall I initiate the channel, or wait for the other person to initiate?
	bool is_backup_channel;

	ChannelConnection connection;

	// SGX SDK remote attestation and key exchange globals
	sgx_ra_context_t context;
	int enclave_lost_retry_time;
	int busy_retry_time;

	sgx_status_t status;
};
typedef struct ChannelStateStruct ChannelState;

// Functions to export
ChannelState *create_channel_state();
void initialise_channel_state(ChannelState *state, bool initiator);
void associate_channel_state(std::string channel_id, ChannelState* state_to_associate);
void remove_association(std::string channel_id);
ChannelState *get_channel_state(std::string channel_id);
bool exists_channel_state(std::string channel_id);
void destroy_channel_state(std::string channel_id);
std::vector<std::string> get_all_channel_ids();
void cleanup();

void send_ra_msg0(ChannelState *channel_state);
void send_ra_msg1(ChannelState *channel_state);
void process_ra_msg0(char* ra_msg, int msg_len);
void process_ra_msg1(char* ra_msg, int ra_msg_len, int sockfd);
void process_ra_msg2(char* ra_msg, int ra_msg_len, int sockfd);
void process_ra_msg3(char* ra_msg, int ra_msg_len, int sockfd);
void process_ra_result(char* ra_msg, int ra_msg_len, int sockfd);

#endif

