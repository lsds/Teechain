#include "sgx_uae_service.h"
#include "teechain_u.h"

#include "channel.h"
#include "network.h"
#include "service_provider.h"
#include "teechain.h"
#include "utils.h"

extern sgx_enclave_id_t global_eid;

std::map<std::string, ChannelState*> channelStates; // map channel ID to state

void init_channel_connection(ChannelConnection* connection) {
	memcpy((char *) connection->id, "", 1);
	memcpy((char *) connection->remote_host, "", 1);
	connection->remote_host_len = 0;
	connection->remote_port = -1;
	connection->remote_sockfd = -1;
}

void init_channel_state(ChannelState* state) {
	init_channel_connection(&(state->connection));
	state->context = -1;
	state->enclave_lost_retry_time = 1;
	state->busy_retry_time = 4;
	state->status = SGX_SUCCESS;
	state->is_initiator = false;
	state->is_backup_channel = false;
}

ChannelState* create_channel_state() {
	//log_debug("create_channel_state() (untrusted)");
	ChannelState *state = (ChannelState*) malloc(sizeof(ChannelState));
	init_channel_state(state);
	return state;
}

void initialise_channel_state(ChannelState* state, bool initiator) {
	state->is_initiator = initiator;
}

void associate_channel_state(std::string channel_id, ChannelState* state_to_associate) {
	memcpy((char*) state_to_associate->connection.id, channel_id.c_str(), CHANNEL_ID_LEN);
	channelStates.insert(std::pair<std::string, ChannelState*>(channel_id, state_to_associate));
}

void remove_association(std::string channel_id) {
        channelStates.erase(channel_id);
}

ChannelState* get_channel_state(std::string channel_id) {
    std::map<std::string, ChannelState*>::iterator it = channelStates.find(channel_id);
    if (it == channelStates.end()) {
        printf("Untrusted get_channel_state() could not find channel state for given channel_id");
        printf("%s", channel_id.c_str());
        printf("Printing contents of channel states!");
        for (std::map<std::string, ChannelState*>::const_iterator it = channelStates.begin(); it != channelStates.end(); it++) {
            print(it->first.c_str());
        }
        error("Failed to get state!! Terminating...");
    }
    return it->second;
}


void destroy_channel_state(std::string channel_id) {
	ChannelState *found;

	std::map<std::string, ChannelState*>::iterator it = channelStates.find(channel_id);
	if (it != channelStates.end()) {
		found = it->second;
	}

	if (found != NULL) {
		channelStates.erase(channel_id);
		free(found);
	}
}

bool exists_state(std::string channel_id) {
	return channelStates.find(channel_id) != channelStates.end();
}

std::vector<std::string> get_all_channel_ids() {
	std::vector<std::string> channel_ids;
	std::map<std::string, ChannelState*>::iterator it;

	for (it = channelStates.begin(); it != channelStates.end(); it++) {
		channel_ids.push_back(it->first);
	}

	return channel_ids;
}

// clean up enclave channel_state
void cleanup() {
    std::vector<std::string> channel_ids = get_all_channel_ids();
    std::vector<std::string>::iterator it;
    for (it = channel_ids.begin(); it != channel_ids.end(); it++) {
        ChannelState *channel_state = get_channel_state(*it);
        if (channel_state->context != -1) {
            int ret;
            ecall_enclave_ra_close(global_eid, (sgx_status_t*) &ret, channel_state->context); // ignore return value
        }
    }

    // destroy SGX enclave channel_state
    sgx_destroy_enclave(global_eid);
}
   
// check the given epid is supported -- for debug enclaves epid is always 0
void process_ra_msg0(char* ra_msg, int msg_len) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) ra_msg;

    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);

    //log_debug("process_ra_msg0(%s)", channel_id.c_str());
    int ret = 0;

    size_t msg0_size = sizeof(ra_samp_request_header_t) + sizeof(sample_ra_msg0_t);
    if (msg0_size != msg_len - sizeof(struct LocalGenericMsg)) {
        error("invalid msg0 request length");
    }

    ra_samp_request_header_t *p_msg0_full = (ra_samp_request_header_t*) msg->blob;

    if (p_msg0_full->type != TYPE_RA_MSG0) {
        error("MSG0 invalid type");
    }

    // verify message 0
    const sample_ra_msg0_t* sample_ra_msg0 = (const sample_ra_msg0_t*) ((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t));
    int sample_ra_msg0_size = p_msg0_full->size;
    int ecall_return;

    ret = ecall_sp_ra_proc_msg0_req(global_eid, &ecall_return, sample_ra_msg0, sample_ra_msg0_size);
    if (ret != 0) {
        error("ecall_sp_ra_proc_msg0_req"); // epid not supported -- terminate handshake
    }
}

// process remote attestation message 1 and send message 2 back to client
void process_ra_msg1(char* ra_msg, int ra_msg_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) ra_msg;

    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);

    //log_debug("process_ra_msg1(%s, %d)", channel_id.c_str(), sockfd);

    int ret = 0;

    size_t msg1_size = sizeof(ra_my_request_header_t) + sizeof(sgx_ra_msg1_t);
    if (msg1_size != ra_msg_len - sizeof(struct LocalGenericMsg)) {
        error("invalid msg1 request length");
    }

    ra_my_request_header_t *p_msg1_full = (ra_my_request_header_t*) msg->blob;

    if (p_msg1_full->header.type != TYPE_RA_MSG1) {
        error("MSG1 invalid type");
    }

    // create memory for message 2
    #define MAX_SIG_RL_SIZE 1024
    uint32_t msg2_size = sizeof(ra_samp_response_header_t) + sizeof(sgx_ra_msg2_t) + MAX_SIG_RL_SIZE;
    ra_samp_response_header_t *p_msg2_full = (ra_samp_response_header_t*) malloc(msg2_size);

#ifdef SGX_ATTEST
    // process message 1
    int ecall_return;
    ret = ecall_sp_ra_proc_msg1_req(global_eid, &ecall_return,
            channel_id.c_str(), channel_id.length(),
            (const sample_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_my_request_header_t)),
            p_msg1_full->header.size, p_msg2_full);

    if (ret != 0 || !p_msg2_full) {
        error("ecall_sp_ra_proc_msg1_req");
    }
#endif

    // send msg2 to the other party
    send_message(OP_REMOTE_RA_MSG2, (char*) channel_id.c_str(), (void*) p_msg2_full, msg2_size, sockfd);
    free(p_msg2_full);
}    

// process message 2 and send message 3
void process_ra_msg2(char* ra_msg, int ra_msg_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) ra_msg;

    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);

    //log_debug("process_ra_msg2(%s,%d)", channel_id.c_str(), sockfd);

    int ret = 0;
    sgx_ra_msg3_t *p_msg3;
    uint32_t msg3_size = 0;

    uint32_t min_msg2_size = sizeof(ra_samp_response_header_t) + sizeof(sgx_ra_msg2_t);
    if (ra_msg_len - sizeof(struct LocalGenericMsg) < min_msg2_size) {
        error("invalid msg2 response length");
    }

    ChannelState *channel_state = get_channel_state(channel_id);

#ifdef SGX_ATTEST
    ra_samp_response_header_t *p_msg2_full = (ra_samp_response_header_t*) msg->blob;

    if (p_msg2_full->type != TYPE_RA_MSG2) {
        error("MSG2 invalid type");
    }

    // process message 2
    sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                                  + sizeof(ra_samp_response_header_t));

    // The ISV app now calls uKE sgx_ra_proc_msg2,
    // The ISV app is responsible for freeing the returned p_msg3!!
    // Retry if SGX_ERROR_BUSY
    int busy_retry_time = 5;
    do {
        ret = sgx_ra_proc_msg2(channel_state->context,
                           global_eid,
                           sgx_ra_proc_msg2_trusted,
                           sgx_ra_get_msg3_trusted,
                           p_msg2_body,
                           p_msg2_full->size,
                           &p_msg3,
                           &msg3_size);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    if (!p_msg3) {
        printf("\nError, call sgx_ra_proc_msg2 fail. "
                        "ret = %x, p_msg3 = 0x%p [%s].", ret, p_msg3, __FUNCTION__);
        if (ret == SGX_ERROR_UNEXPECTED) {
            printf("An unexpected error occurred -- not helpful!");
        } else if (ret == SGX_ERROR_BUSY) {
            printf("SGX IS BUSY!");
        } else if (ret == SGX_ERROR_MAC_MISMATCH) {
            printf("Mac mismatch!");
        }
        error("sgx_ra_proc_msg2");
    }
#endif

    // build full message 3 request
    int msg3_full_size = sizeof(ra_samp_request_header_t) + msg3_size;
    ra_samp_request_header_t *p_msg3_full = (ra_samp_request_header_t*) malloc(msg3_full_size);
    if (p_msg3_full == NULL) {
        error("p_msg3_full");
    }
    p_msg3_full->type = TYPE_RA_MSG3;
    p_msg3_full->size = msg3_size;

    if(memcpy_s(p_msg3_full->body, msg3_size, p_msg3, msg3_size)) {
        error("memcpy: msg3");
    }

    // send msg3 to the other party
    send_message(OP_REMOTE_RA_MSG3, (char*) channel_id.c_str(), (void*) p_msg3_full, msg3_full_size, sockfd);
    free(p_msg3_full);

#ifdef SGX_ATTEST
    free(p_msg3);
#endif
}

void process_ra_result(char* ra_msg, int ra_msg_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) ra_msg;

    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);

    //log_debug("process_ra_result(%s,%d)", channel_id.c_str(), sockfd);
    int ret = 0;
    int result_msg_size = sizeof(ra_samp_response_header_t) + sizeof(sample_ra_att_result_msg_t) + SUCC_ATT_MESSAGE_SIZE;

    ChannelState *channel_state = get_channel_state(channel_id);

#ifdef SGX_ATTEST
    if (result_msg_size != ra_msg_len - sizeof(struct LocalGenericMsg)) {
        error("invalid result message length");
    }

    ra_samp_response_header_t *p_att_result_msg_full = (ra_samp_response_header_t*) msg->blob;

    if (p_att_result_msg_full->type != TYPE_RA_ATT_RESULT) {
        error("p_att_result_msg_full type is not valid!");
    }

    sample_ra_att_result_msg_t * p_att_result_msg_body =
        (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
                                       + sizeof(ra_samp_response_header_t));

    // Check the MAC using MK on the attestation result message.
    // The format of the attestation result message is ISV specific.
    // This is a simple form for demonstration. In a real product,
    // the ISV may want to communicate more information.
    ret = ecall_verify_att_result_mac(global_eid, &(channel_state->status), channel_state->context,
            (uint8_t*)&p_att_result_msg_body->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_att_result_msg_body->mac,
            sizeof(sgx_mac_t));
    if ((ret != SGX_SUCCESS) || (channel_state->status != SGX_SUCCESS)) {
        error("verify_att_result_mac");
    }

    // Check the attestation result for pass or fail.
    // Whether attestation passes or fails is a decision made by the ISV Server.
    // When the ISV server decides to trust the enclave, then it will return success.
    // When the ISV server decided to not trust the enclave, then it will return failure.
    if (0 != p_att_result_msg_full->status[0] || 0 != p_att_result_msg_full->status[1]) {
        error("attestation result message MK based cmac failed");
     }

    // The attestation result message should contain a field for the Platform
    // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
    // It is not returned in all cases, but when it is, the ISV app
    // should pass it to the blob analysis API called sgx_report_attestation_status()
    // along with the trust decision from the ISV server.
    // The ISV application will take action based on the update_info.
    // returned in update_info by the API.  
    // This call is stubbed out for the sample.
    // 
    // sgx_update_info_bit_t update_info;
    // ret = sgx_report_attestation_status(
    //     &p_att_result_msg_body->platform_info_blob,
    //     attestation_passed ? 0 : 1, &update_info);

    // Get the shared secret sent by the server using SK (if attestation
    // passed)

    ret = ecall_put_secret_data(global_eid, &(channel_state->status), channel_state->context,
                          p_att_result_msg_body->secret.payload,
                          p_att_result_msg_body->secret.payload_size,
                          p_att_result_msg_body->secret.payload_tag);
    if ((ret != SGX_SUCCESS)  || (channel_state->status != SGX_SUCCESS)) {
        error("ecall_put_secret_data");
    }

    //print_important("Remote attestation success!");
#endif

    // if non initiator, then both enclaves have attested to eachother
    if (!channel_state->is_initiator) {
        if (channel_state->is_backup_channel) {
            generate_and_send_encrypted_backup_state(channel_state);
            // Get user output in case we need to return to the user command line process
            char user_output[MAX_ECALL_RETURN_LENGTH];
            get_user_output_for_channel(channel_id, user_output);
            send_ack(channel_state->connection.local_sockfd, OP_LOCAL_ACK, user_output);
        } else {
            generate_and_send_encrypted_deposit_data(channel_state);
        }
        channel_state->connection.remote_sockfd = sockfd;
    }
}

// Preparation for remote attestation by configuring extended epid group id and sending
// to opposite enclave.
void send_ra_msg0(ChannelState *channel_state) {
    //log_debug("send_ra_msg0(%s)", std::string(channel_state->connection.id, CHANNEL_ID_LEN).c_str());

    uint32_t extended_epid_group_id = 0;
    int ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
    if (SGX_SUCCESS != ret) {
        error("sgx_get_extended_epid_group_id");
    }

    size_t msg0_size = sizeof(ra_samp_request_header_t) + sizeof(sample_ra_msg0_t);
    ra_samp_request_header_t *p_msg0_full = (ra_samp_request_header_t*) malloc(msg0_size);
    if (p_msg0_full == NULL) {
        error("malloc");
    }

    // fill message 0 and body
    p_msg0_full->type = TYPE_RA_MSG0;
    p_msg0_full->size = sizeof(sample_ra_msg0_t);
    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_samp_request_header_t)) = extended_epid_group_id;

    // send message 0 to the other enclave.
    send_message(OP_REMOTE_RA_MSG0, (char*) channel_state->connection.id, (void*) p_msg0_full, msg0_size, channel_state->connection.remote_sockfd);
    free(p_msg0_full);
}

void send_ra_msg1(ChannelState *channel_state) {
    //log_debug("send_ra_msg1(%s)", std::string(channel_state->connection.id, CHANNEL_ID_LEN).c_str());

    // generate ra context
    int ret = ecall_enclave_init_ra(global_eid, &channel_state->status, false, &channel_state->context);
    if (ret != SGX_SUCCESS || channel_state->status) {
        error("enclave_init_ra");
    }

    // create memory for message 1 to be sent next
    size_t msg1_size = sizeof(ra_my_request_header_t) + sizeof(sgx_ra_msg1_t);
    ra_my_request_header_t *p_msg1_full = (ra_my_request_header_t*) malloc(msg1_size);
    if (p_msg1_full == NULL) {
        error("malloc");
    }

    // fill message 1 and body
    p_msg1_full->header.type = TYPE_RA_MSG1;
    p_msg1_full->header.size = sizeof(sgx_ra_msg1_t);
    sgx_ra_msg1_t* msg1_body = (sgx_ra_msg1_t*) ((uint8_t*) p_msg1_full + sizeof(ra_my_request_header_t));
    do {
        ret = sgx_ra_get_msg1(channel_state->context, global_eid, sgx_ra_get_ga, msg1_body);
    } while (SGX_ERROR_BUSY == ret && channel_state->busy_retry_time--);

    if (ret != SGX_SUCCESS) {
        error("sgx_ra_get_msg1");
    }

    // send message 1 to the other enclave.
    send_message(OP_REMOTE_RA_MSG1, (char *) channel_state->connection.id, (void*) p_msg1_full, msg1_size, channel_state->connection.remote_sockfd);
    free(p_msg1_full);
}    

void process_ra_msg3(char* ra_msg, int ra_msg_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) ra_msg;

    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);

    //log_debug("process_ra_msg3(%s,%d)", channel_id.c_str(), sockfd);
    int ret = 0;

    ra_samp_request_header_t *p_msg3_full = (ra_samp_request_header_t*) msg->blob;

    ChannelState *channel_state = get_channel_state(channel_id);

    // malloc memory
    int result_msg_size = sizeof(ra_samp_response_header_t) + sizeof(sample_ra_att_result_msg_t) + SUCC_ATT_MESSAGE_SIZE;
    ra_samp_response_header_t *p_att_result_msg_full = (ra_samp_response_header_t*) malloc(result_msg_size);

#ifdef SGX_ATTEST
    if (p_msg3_full->type != TYPE_RA_MSG3) {
        error("MSG3 invalid type");
    }

    int ecall_return;
    ret = ecall_sp_ra_proc_msg3_req(global_eid, &ecall_return,
        channel_id.c_str(), channel_id.length(),
        (const sample_ra_msg3_t*)((uint8_t*)p_msg3_full + sizeof(ra_samp_request_header_t)),
        p_msg3_full->size, p_att_result_msg_full);
    if (ret != 0) {
        error("ecall_sp_rc_proc_msg3_req");
    }

    if (!p_att_result_msg_full) {
        error("p_att_result_msg_full");
    }
#endif

    // send RA result to the other party
    send_message(OP_REMOTE_RA_RESULT, (char *) channel_id.c_str(), (void*) p_att_result_msg_full, result_msg_size, sockfd);

    free(p_att_result_msg_full);

    // non-initiator's turn to attest to the initiator
    if (!channel_state->is_initiator) {
        channel_state->connection.remote_sockfd = sockfd;
        memcpy((void*)channel_state->connection.id, (void*)channel_id.c_str(), CHANNEL_ID_LEN);
        perform_handshake(channel_state);
    }
}

