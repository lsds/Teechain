#include "channel.h"
#include "network.h"
#include "teechain_u.h"
#include "teechain.h"
#include "utils.h"

extern sgx_enclave_id_t global_eid;

void backup(char *data, int client_fd) {
    //log_debug("backup()");

    int ecall_return;
    int command_return = ecall_backup(global_eid, &ecall_return);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_backup");
        error("ecall_backup");
    }

    send_ack(client_fd, OP_LOCAL_ACK, "");
}

void generate_and_send_encrypted_backup_state(ChannelState *channel_state) {
    std::string channel_id(channel_state->connection.id, CHANNEL_ID_LEN);
    //log_debug("generate_and_send_encrypted_backup_state()");

    char encrypted_data[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    int ecall_return;
    int command_return = ecall_get_backup_data_encrypted(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), encrypted_data, &encrypted_data_len, p_gcm_mac);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_get_backup_data_encrypted");
    }
    
    send_encrypted_message(OP_REMOTE_BACKUP_DATA, (char *) channel_state->connection.id, encrypted_data, encrypted_data_len, p_gcm_mac, channel_state->connection.remote_sockfd);
}


void process_backup_data(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_backup_data(%s)", channel_id.c_str());

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_store_encrypted_backup_data(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_store_encrypted_backup_data");
    }

    if (ecall_return == REQUEST_FAILED) {
        printf("ecall_store_encrypted_backup_data unable to process request!");
        return; // don't ack -- just ignore the request
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);
    if (send_action == SEND_LOCAL_ACK) { // send ack to local rpc client
        std::string output = "A backup channel has been created!\n";
        output += "Backup Channel ID: " + channel_id + ".\n";
        return send_ack(channel_state_to_send_on->connection.local_sockfd, OP_LOCAL_ACK, output.c_str());
    }

    int message_operation;
    if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_BACKUP_DATA;
    } else if (send_action == SEND_SECURE_ACK) {
        message_operation = OP_REMOTE_BACKUP_DATA_ACK;
    } else {
        error("Invalid send_action");
    }
    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

void process_update_channel_balance(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_update_channel_balance(%s,%d)", channel_id.c_str(), sockfd);

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_store_encrypted_channel_update_data(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_store_encrypted_channel_update_data");
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    // send message to remote (either backup or next channel)
    int message_operation;
    if (send_action == SEND_UPDATE_CHANNEL_BALANCE_REQUEST) {
        message_operation = OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA;
    } else if (send_action == SEND_UPDATE_CHANNEL_BALANCE_ACK) {
        message_operation = OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA_ACK;
    } else {
        error("Invalid send_action");
    }

    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

void process_remove_backup(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    //log_debug("process_remove_backup(%s,%d)", channel_id.c_str(), sockfd);

    ChannelState *channel_state = get_channel_state(channel_id);
    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_remove_remote_backup(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_remove_backup_channel");
    }

    send_encrypted_message(OP_REMOTE_REMOVE_BACKUP_ACK, (char *) channel_state->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state->connection.remote_sockfd);
}

void process_remove_backup_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_remove_backup_ack(%s,%d)", channel_id.c_str(), sockfd);

    char *real_data = msg->blob;
    int real_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_verify_backup_removed(global_eid, &ecall_return, real_data, real_len, channel_state->context);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_verify_backup_removed");
    }

    // send ack to local sockfd to notify that the backup was successfully added to the channel
    send_ack(channel_state->connection.local_sockfd, OP_LOCAL_ACK, "removed backup");
}

void process_backup_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_backup_ack(%s,%d)", channel_id.c_str(), sockfd);

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    char next_hop_channel_id[CHANNEL_ID_LEN];
    bool routing_complete = false;
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    int ecall_return;
    int command_return = ecall_verify_backup_stored(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, next_hop_channel_id, &routing_complete, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_verify_backup_stored");
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);
    if (ecall_return == REQUEST_FAILED) {
        printf("Backup request failed somewhere along the backup path!");
        return send_ack(channel_state_to_send_on->connection.local_sockfd, OP_LOCAL_ACK, "failed to get backup_ack");
    }

    if (send_action == SEND_LOCAL_ACK) {
        return send_ack(channel_state_to_send_on->connection.local_sockfd, OP_LOCAL_ACK, "processed_backup_ack");
    } else if (send_action == SEND_CHANNEL_CREATE_ACK) {  // channel created my side
        if (channel_state_to_send_on->is_initiator) {
            generate_and_send_encrypted_deposit_data(channel_state_to_send_on);
        }
        char user_output[MAX_ECALL_RETURN_LENGTH];
        get_user_output_for_channel(channel_id_to_send_on_s, user_output);
        return send_ack(channel_state_to_send_on->connection.local_sockfd, OP_LOCAL_ACK, user_output);
    } else if (send_action == SEND_INSECURE_ACK) {
        return send_message(OP_REMOTE_SEND_ACK, (char *) channel_state_to_send_on->connection.id, NULL, 0, channel_state_to_send_on->connection.remote_sockfd);
    }

    int message_operation;
    if (send_action == SEND_SECURE_ACK) {
        message_operation = OP_REMOTE_BACKUP_DATA_ACK;

    } else if (send_action == SEND_DEPOSIT_ADD_REQUEST) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_ADD;
    } else if (send_action == SEND_DEPOSIT_ADD_ACK) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK;

    } else if (send_action == SEND_DEPOSIT_REMOVE_REQUEST) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE;
    } else if (send_action == SEND_DEPOSIT_REMOVE_ACK) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK;

    } else if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_SEND;

    } else {
        error("Invalid send_action");
    }

    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

void remove_backup(char* data, int client_fd) {
    struct LocalRemoveBackupMsg msg = *((struct LocalRemoveBackupMsg*) (data));
    std::string channel_id(msg.backup_channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("Channel id: %s", channel_id.c_str());
    
    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    int ecall_return;
    int command_return = ecall_remove_backup(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), encrypted_data_out, &encrypted_data_out_len, p_gcm_mac);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_remove_backup");
    }

    send_encrypted_message(OP_REMOTE_REMOVE_BACKUP, (char *) channel_state->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state->connection.remote_sockfd);
    // save local sockfd so we can ack when the backup has been removed
    channel_state->connection.local_sockfd = client_fd;
}
