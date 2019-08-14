#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <sys/time.h>
#include "time.h"

#include <sstream>
#include <algorithm>
#include <iterator>
#include <tuple>

#include <sgx_urts.h>
#include "sgx_ukey_exchange.h"
#include "sgx_uae_service.h"

#include "network.h"
#include "service_provider.h"
#include "sgx_utils.h"
#include "teechain_u.h"
#include "teechain.h"
#include "utils.h"
#include "backups.h"

extern bool debug;
extern bool benchmark;

int error_count = 0; // useful for catching errors and terminating enclave correctly

// Global EID shared by multiple threads
sgx_enclave_id_t global_eid = 0;

struct timeval debug_start;
struct timeval debug_end;

static sgx_enclave_id_t get_enclave() {
    return global_eid;
}

int initialize_enclave() {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    if (home_dir != NULL &&
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(TEECHAN_SEC_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_sgx_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == 0 || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}

// sends the given message on the socket, with the appropriate message operation
void send_message(uint32_t operation, char *channel_id, void* blob_pointer, int blob_size, int sockfd) {
    size_t msg_len = sizeof(struct LocalGenericMsg) + blob_size;
    char msg_memory[msg_len];

    // fill message memory with data and encrypted blob
    struct LocalGenericMsg *msg = (struct LocalGenericMsg *) &msg_memory;
    msg->msg_op[0] = operation;
    memcpy(msg->channel_id, channel_id, CHANNEL_ID_LEN);
    memcpy(msg->blob, blob_pointer, blob_size);

    send_on_socket(msg_memory, msg_len, sockfd);
}

void send_encrypted_message(uint32_t operation, char* channel_id, char* encrypted_data, int encrypted_data_len, char* p_gcm_mac, int sockfd) {
    int mac_and_data_len = SAMPLE_SP_TAG_SIZE + encrypted_data_len;
    char mac_and_data[mac_and_data_len];

    std::copy(p_gcm_mac, p_gcm_mac + SAMPLE_SP_TAG_SIZE, mac_and_data);
    std::copy(encrypted_data, encrypted_data + encrypted_data_len, mac_and_data + SAMPLE_SP_TAG_SIZE);

    send_message(operation, channel_id, (void*) mac_and_data, mac_and_data_len, sockfd);
}

// sends an ack response indicating success or failure along the socket
void send_ack(int sockfd, int response, const char *info_msg) {
    if (!info_msg) {
        error("Cannot provide empty info_msg for ack!");
    }

    int info_msg_len = strlen(info_msg);
    unsigned long msg_length = info_msg_len + 1;
    char msg[msg_length];
    msg[0] = response;
    memcpy((void*) &(msg[1]), info_msg, info_msg_len);
    
    send_on_socket(msg, msg_length, sockfd);
    if (info_msg_len > 0) {
        // Print message to log!
        print(info_msg);
    }
}

static void wait_for_send_ack(int sockfd) {
    char response[MAX_ECALL_SEND_RETURN_LENGTH];
    read_from_socket(sockfd, response, MAX_ECALL_SEND_RETURN_LENGTH);

    if (response[MSG_LEN_BYTES] == OP_LOCAL_ACK) {
        log_debug("Got ack for: " + response[MSG_LEN_BYTES]);
    } else {
        std::string message = "Failure ack received: " + response[MSG_LEN_BYTES];
        error(message);
    }
}

static void settle(char *data, int client_fd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    //log_debug("settle(%s)", channel_id.c_str());

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_settle(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), user_output);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_settle");
        error("ecall_settle");
    }

    if (ecall_return == REQUEST_FAILED) {
        printf("Unable to settle channel!");
        send_ack(client_fd, OP_LOCAL_ACK, "Unable to settle channel");
        return;
    }

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

static void return_unused_deposits(char *data, int client_fd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    //log_debug("return_unused_deposits()");

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_return_deposits(global_eid, &ecall_return, user_output);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_return_deposits");
        error("ecall_return_deposits");
    }

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

void shutdown_enclave(char* user_output) {
    int ecall_return;
    int command_return = ecall_shutdown(global_eid, &ecall_return, user_output);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_shutdown");
    }
}

static void shutdown(char *data, int client_fd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    //log_debug("shutdown()");

    char user_output[MAX_ECALL_RETURN_LENGTH];
    shutdown_enclave(user_output);

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
    sgx_destroy_enclave(global_eid);
    exit(0); 
}

static void primary(char *data, int client_fd) {
    struct LocalAssignmentMsg *msg = (struct LocalAssignmentMsg*) data;
    //log_debug("primary()");

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_primary(global_eid, &ecall_return, msg->use_monotonic_counters, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_primary");
        error("ecall_primary");
    }

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

static void balance(char *data, int client_fd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    //log_debug("balance(%s)", channel_id.c_str());

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_balance(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), user_output);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_balance");
        error("ecall_channel_balance");
    }

   if (ecall_return == REQUEST_FAILED) {
       printf("Unable to print balance!");
   }

   send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

static void verify_deposits(char *data, int client_fd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    //log_debug("verify_deposits(%s)", channel_id.c_str());

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_verify_deposits(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        send_ack(client_fd, OP_LOCAL_FAIL, "ecall_verify_deposits");
        error("ecall_verify_deposits");
    }

    // send insecure established ack to remote party
    ChannelState *channel_state = get_channel_state(channel_id);
    send_message(OP_REMOTE_VERIFY_DEPOSITS_ACK, (char *) channel_state->connection.id, NULL, 0, channel_state->connection.remote_sockfd);

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

void generate_and_send_encrypted_deposit_data(ChannelState *channel_state) {
    //log_debug("generate_and_send_encrypted_deposit_data()");

    std::string channel_id(channel_state->connection.id, CHANNEL_ID_LEN);
    char encrypted_data[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    int ecall_return;
    int command_return = ecall_get_deposit_data_encrypted(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), encrypted_data, &encrypted_data_len, p_gcm_mac);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_get_deposit_data_encrypted");
    }
   
    send_encrypted_message(OP_REMOTE_CHANNEL_CREATE_DATA, (char *) channel_state->connection.id, encrypted_data, encrypted_data_len, p_gcm_mac, channel_state->connection.remote_sockfd);
}

// This function does not need to be secure -- the channel ID's are nothing but handles.
// How they are derived is unimportant. We just generate one randomly for ease of use.
static std::string generate_channel_id() {
    std::ostringstream os;
    srand(time(NULL));
    for (int i = 0; i < CHANNEL_ID_LEN; ++i) {
        int digit = rand() % 10;
	os << digit;
    }
    std::string generated_channel_id = os.str();
    //log_debug("Generated channel id: %s\n", generated_channel_id.c_str()); 
    return os.str();
}

// starts the SDK diffie-hellman handshake and remote attestation exchange
void perform_handshake(ChannelState *channel_state) {
    if (is_valid_port(channel_state->connection.remote_port)) {
        //log_debug("Initiating handshake with %s:%d", std::string(channel_state->connection.remote_host, channel_state->connection.remote_host_len).c_str(), channel_state->connection.remote_port);
    }
    else {
        //log_debug("Initiating handshake with the other end");
    }

    send_ra_msg0(channel_state); // send the epid to the other enclave
    send_ra_msg1(channel_state); // send message 1 to the other enclave
}

static void ghost_enclave() {
    if (initialize_enclave() < 0){
        error("initialize_enclave");
    }

    if (debug) {
        int ecall_return;
        int command_return = ecall_debug_enclave(global_eid, &ecall_return);
        if (command_return != SGX_SUCCESS || ecall_return != 0) {
            error("ecall_debug_enclave");
        }
    }

    if (benchmark) {
        int ecall_return;
        int command_return = ecall_benchmark_enclave(global_eid, &ecall_return);
        if (command_return != SGX_SUCCESS || ecall_return != 0) {
            error("ecall_benchmark_enclave");
        }
    }
}

void register_new_connection(int conn_sock) {
    event.events = EPOLLIN;
    event.data.fd = conn_sock;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_sock, &event) < 0) {
        error("epoll_ctl");
    }

    // let's get the peer's IP address
    socklen_t len;
    struct sockaddr_storage addr;
    char ipstr[INET6_ADDRSTRLEN];
    int remoteport, islocalhost = 0;

    len = sizeof addr;
    //TODO: use clientaddr
    getpeername(conn_sock, (struct sockaddr*)&addr, &len);

    // deal with both IPv4 and IPv6:
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        remoteport = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
        islocalhost = (strcmp(ipstr, "127.0.0.1") == 0);
    } else { // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        remoteport = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
        islocalhost = (strcmp(ipstr, "::1") == 0);
    }

    // TODO(joshlind): remove once we understand why getpeername
    // is returning the private IP instead of localhost?
    // printf("Peer IP address: %s\n", ipstr);
    if (!islocalhost) {
        islocalhost = (strcmp(ipstr, "192.168.0.101") == 0);
    } 

    // initialize a connection, indexed by the file descriptor
    connections[conn_sock].fd = conn_sock;
    connections[conn_sock].inuse = 1;
    connections[conn_sock].islocalhost = islocalhost;
    connections[conn_sock].input.clear();
}

static void accept_new_connection(int server) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    int conn_sock = accept(server, (struct sockaddr *) &clientaddr, &addrlen);
    if (conn_sock < 0) {
        error("accept");
    }

    register_new_connection(conn_sock);
}

static void close_socket(int client_fd) {
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, &event) < 0) {
        error("epoll_ctl: EPOLL_CTL_DEL");    
    }

    connections[client_fd].fd = 0;
    connections[client_fd].inuse = 0;
    connections[client_fd].islocalhost = 0;
    connections[client_fd].input.clear();
    close(client_fd);
}

static void process_channel_id_generated(char* data, int data_len) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    bool* is_backup = (bool*) &(msg->blob);
    //log_debug("process_channel_id_generated(%s)", channel_id.c_str());

    // Update association
    std::string temp_channel_id(TEMPORARY_CHANNEL_ID, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(temp_channel_id);
    remove_association(temp_channel_id);
    associate_channel_state(channel_id, channel_state);

    // Update channel id inside enclave
    int ecall_return;
    int command_return = ecall_channel_id_generated(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), *is_backup);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_channel_id_generated");
    }
}

static void process_channel_create_data(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_channel_create_data(%s)", channel_id.c_str());

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_store_encrypted_deposit_data(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_store_encrypted_deposit_data");
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    if (send_action == SEND_LOCAL_ACK) {
        if (channel_state->is_initiator) { // allow other side to get my channel create data
            generate_and_send_encrypted_deposit_data(channel_state);
        }
        // Get user output in case we need to return to the user command line process
        char user_output[MAX_ECALL_RETURN_LENGTH];
        get_user_output_for_channel(channel_id, user_output);
        send_ack(channel_state_to_send_on->connection.local_sockfd, OP_LOCAL_ACK, user_output);
    } else if (send_action == SEND_BACKUP_STORE_REQUEST) {
        send_encrypted_message(OP_REMOTE_BACKUP_DATA, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
    } else {
        error("Invalid send_action!");
    }
}

static void process_verify_deposits_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);

    int ecall_return;
    int command_return = ecall_remote_verify_deposits(global_eid, &ecall_return, channel_id.c_str(), channel_id.length());
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_remote_verify_deposits");
    }
}

void get_user_output_for_channel(std::string channel_id, char* user_output) {
    int ecall_return;
    int command_return = ecall_get_user_output(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_get_user_output");
    }
}

static void process_send_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    send_ack(channel_state->connection.local_sockfd, OP_LOCAL_ACK, "");

    if (!benchmark) {
        printf("Your payment has been sent!\n");
    }
}

static void process_send_request(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);

    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    char encrypted_data_out[MAX_ECALL_SEND_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char user_output[MAX_ECALL_USER_OUTPUT];
    int ecall_return;
    int command_return = ecall_receive_bitcoins(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_receive_bitcoins");
    }

    if (!benchmark) {
        // print amount received
        printf("%s", user_output);
    }

    if (send_action == SEND_INSECURE_ACK) {
        // send insecure received ack to remote party
        send_message(OP_REMOTE_SEND_ACK, (char *) channel_state->connection.id, NULL, 0, channel_state->connection.remote_sockfd);
        return;
    } else if (send_action == SEND_UPDATE_CHANNEL_BALANCE_REQUEST) {
        // send backup sync request
        std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
        ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);
        send_encrypted_message(OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
    } else {
        error("ecall_receive_bitcoins did not return any message to forward!");
    }

}

static void process_deposit_remove(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_deposit_remove(%s,%d)", channel_id.c_str(), sockfd);

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_remove_remote_deposit_from_channel(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_remove_remote_deposit_from_channel");
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    int message_operation;
    if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_BACKUP_DATA;
    } else if (send_action == SEND_DEPOSIT_REMOVE_ACK) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK;
    } else {
        error("invalid send_action");
    }
    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

static void process_deposit_add(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);
    //log_debug("process_deposit_add(%s,%d)", channel_id.c_str(), sockfd);

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    int ecall_return;
    int command_return = ecall_add_remote_deposit_to_channel(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_add_remote_deposit_to_channel");
    }

    if (ecall_return == REQUEST_FAILED) {
        printf("Unable to add deposit request according to remote!");
        return;
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    int message_operation;
    if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_BACKUP_DATA;
    } else if (send_action == SEND_DEPOSIT_ADD_ACK) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK;
    } else {
        error("invalid send_action");
    }
    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

static void process_deposit_remove_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id.c_str());
    //log_debug("process_deposit_remove_ack(%s,%d)", channel_id.c_str(), sockfd);

    char *real_data = msg->blob;
    int real_len = data_len - sizeof(struct LocalGenericMsg);
    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_verify_deposit_removed_from_channel(global_eid, &ecall_return, real_data, real_len, channel_state->context, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_verify_deposit_removed_from_channel");
    }

    send_ack(channel_state->connection.local_sockfd, OP_LOCAL_ACK, user_output);
}

static void process_deposit_add_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id.c_str());
    //log_debug("process_deposit_add_ack(%s,%d)", channel_id.c_str(), sockfd);

    char *real_data = msg->blob;
    int real_len = data_len - sizeof(struct LocalGenericMsg);
    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_verify_deposit_added_to_channel(global_eid, &ecall_return, real_data, real_len, channel_state->context, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_verify_deposit_added_to_channel");
    }

    send_ack(channel_state->connection.local_sockfd, OP_LOCAL_ACK, user_output);
}

static void process_update_channel_balance_ack(char* data, int data_len, int sockfd) {
    struct LocalGenericMsg *msg = (struct LocalGenericMsg*) data;
    std::string channel_id(msg->channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id.c_str());
    //log_debug("process_update_channel_balance_ack(%s,%d)", channel_id.c_str(), sockfd);

    char *blob_data = msg->blob;
    int blob_len = data_len - sizeof(struct LocalGenericMsg);
    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    int ecall_return;
    int command_return = ecall_verify_channel_update_stored(global_eid, &ecall_return, blob_data, blob_len, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_state->context, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_verify_channel_update_stored");
    }

    // get channel_state for next channel in payment route and send message
    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    if (send_action == SEND_INSECURE_ACK) {
        // send insecure received ack to remote party
        return send_message(OP_REMOTE_SEND_ACK, (char *) channel_state_to_send_on->connection.id, NULL, 0, channel_state_to_send_on->connection.remote_sockfd);
    }

    int message_operation;
    if (send_action == SEND_UPDATE_CHANNEL_BALANCE_ACK) {
        message_operation = OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA_ACK;
    } else if (send_action == SEND_BITCOIN_PAYMENT) {
        message_operation = OP_REMOTE_SEND;
    } else {
        error("Invalid send_action");
    }

    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);
}

static void send(char* data, int sockfd) {
    struct LocalSendMsg msg = *((struct LocalSendMsg*) data);
    unsigned long long amount = msg.amount;
    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    ChannelState *channel_state = get_channel_state(channel_id);

    char send_req[MAX_ECALL_SEND_RETURN_LENGTH];
    int send_req_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    int ecall_return;
    int command_return = ecall_send_bitcoins(global_eid, &ecall_return, msg.channel_id, CHANNEL_ID_LEN, amount, send_req, &send_req_len, p_gcm_mac, channel_id_to_send_on, &send_action);

    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        send_ack(sockfd, OP_LOCAL_FAIL, "ecall_send_bitcoins failed");
        return;
    }

    if (ecall_return == REQUEST_FAILED) {
        send_ack(sockfd, OP_LOCAL_ACK, "send request failed");
        return; // don't error -- request failed
    }

    // get channel_state for next channel in payment route and send message
    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    int message_operation;
    if (send_action == SEND_UPDATE_CHANNEL_BALANCE_REQUEST) {
        message_operation = OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA;
    } else if (send_action == SEND_BITCOIN_PAYMENT) {
        message_operation = OP_REMOTE_SEND;
    } else {
        error("Invalid send_action");
    }

    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, send_req, send_req_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);

    // save local sockfd so we can ack when the bitcoins are sent!
    channel_state->connection.local_sockfd = sockfd;
}

// provisions the primary enclave with the number of deposits to create
static void setup_deposits(char* data, int client_fd) {
    struct LocalSetupDepositsMsg msg = *((struct LocalSetupDepositsMsg*) (data));
    unsigned long long num_deposits = msg.num_deposits;
    //log_debug("Num deposits: %llu", num_deposits);

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_setup_deposits(global_eid, &ecall_return, msg.num_deposits, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_setup_deposits");
    }

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

// provisions the primary enclave with setup and deposit information after the user has already 
// created the funding transaction
static void deposits_made(char* data, int client_fd) {
    struct LocalDepositsMadeMsg msg = *((struct LocalDepositsMadeMsg*) (data));
    unsigned long long miner_fee = msg.miner_fee;
    unsigned long long num_deposits = msg.num_deposits;

    char txids[MAX_NUM_SETUP_DEPOSITS * BITCOIN_TX_HASH_LEN] = {};  // 0 array
    unsigned long long tx_indexes[MAX_NUM_SETUP_DEPOSITS];
    unsigned long long deposit_amounts[MAX_NUM_SETUP_DEPOSITS];

    for (unsigned long long i = 0; i < num_deposits; i++) {
        struct LocalDepositMadeMsg local_deposit = msg.deposits[i];

        unsigned long long tx_index = local_deposit.tx_index;
        unsigned long long deposit_amount = local_deposit.deposit_amount;

        tx_indexes[i] = tx_index;
        deposit_amounts[i] = deposit_amount;
        memcpy(&txids[i * BITCOIN_TX_HASH_LEN], local_deposit.txid, BITCOIN_TX_HASH_LEN);
    }

    int txids_len = BITCOIN_TX_HASH_LEN * MAX_NUM_SETUP_DEPOSITS; // in bytes
    int tx_indexes_len = sizeof(unsigned long long) * MAX_NUM_SETUP_DEPOSITS; // in bytes
    int deposit_amounts_len = sizeof(unsigned long long) * MAX_NUM_SETUP_DEPOSITS; // in bytes

    char user_output[MAX_ECALL_RETURN_LENGTH];
    int ecall_return;
    int command_return = ecall_deposits_made(global_eid, &ecall_return, msg.my_address, BITCOIN_ADDRESS_LEN, miner_fee, num_deposits, txids, txids_len, tx_indexes, tx_indexes_len, deposit_amounts, deposit_amounts_len, user_output);
    if (command_return != SGX_SUCCESS || ecall_return != 0) {
        error("ecall_deposits_made");
    }

    send_ack(client_fd, OP_LOCAL_ACK, user_output);
}

static void remove_deposit(char* data, int client_fd) {
    struct LocalDepositMsg msg = *((struct LocalDepositMsg*) (data));
    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id = msg.deposit_id;
    ChannelState *channel_state = get_channel_state(channel_id);

    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    int ecall_return;
    int command_return = ecall_remove_deposit_from_channel(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), deposit_id, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_remove_deposit_from_channel");
    }

    if (ecall_return == REQUEST_FAILED) {
        printf("Failed to remove deposit from channel. Check balance, or try again\n");
        send_ack(client_fd, OP_LOCAL_ACK, "remove deposit");
        return;
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    int message_operation;
    if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_BACKUP_DATA;
    } else if (send_action == SEND_DEPOSIT_REMOVE_REQUEST) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE;
    } else {
        error("Invalid send_action");
    }
    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);

    // save local sockfd so we can ack when the remote successfully adds the deposit
    channel_state->connection.local_sockfd = client_fd;
}

static void add_deposit(char* data, int client_fd) {
    struct LocalDepositMsg msg = *((struct LocalDepositMsg*) (data));
    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);
    unsigned long long deposit_id = msg.deposit_id;
    ChannelState *channel_state = get_channel_state(channel_id);

    // assign deposit to channel in our enclave and then request a secure ack from the remote party that they added it too
    char encrypted_data_out[MAX_ECALL_RETURN_LENGTH];
    int encrypted_data_out_len;
    char p_gcm_mac[SAMPLE_SP_TAG_SIZE];
    char channel_id_to_send_on[CHANNEL_ID_LEN];
    int send_action;
    int ecall_return;
    int command_return = ecall_add_deposit_to_channel(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), deposit_id, encrypted_data_out, &encrypted_data_out_len, p_gcm_mac, channel_id_to_send_on, &send_action);
    if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
        error("ecall_add_deposit_to_channel");
    }

    if (ecall_return == REQUEST_FAILED) {
        printf("Unable to add deposit! Check deposit index, or try again\n");
        send_ack(client_fd, OP_LOCAL_ACK, "");
        return;
    }

    std::string channel_id_to_send_on_s(channel_id_to_send_on, CHANNEL_ID_LEN);
    ChannelState *channel_state_to_send_on = get_channel_state(channel_id_to_send_on_s);

    int message_operation;
    if (send_action == SEND_BACKUP_STORE_REQUEST) {
        message_operation = OP_REMOTE_BACKUP_DATA;
    } else if (send_action == SEND_DEPOSIT_ADD_REQUEST) {
        message_operation = OP_REMOTE_TEECHAIN_DEPOSIT_ADD;
    } else {
        error("Invalid send_action");
    }
    send_encrypted_message(message_operation, (char *) channel_state_to_send_on->connection.id, encrypted_data_out, encrypted_data_out_len, p_gcm_mac, channel_state_to_send_on->connection.remote_sockfd);

    // save local sockfd so we can ack when the remote successfully adds the deposit
    channel_state->connection.local_sockfd = client_fd;
}

// creates a new channel
static void create(bool is_backup, char* data, int client_fd) {
    struct LocalCreateMsg msg = *((struct LocalCreateMsg*) (data));
    std::string channel_id(msg.channel_id, CHANNEL_ID_LEN);

    if (msg.initiator) {
        channel_id = generate_channel_id();  // We overwrite the temporary channel id handle
    }

    int ecall_return;
    if (is_backup) {
        int command_return = ecall_create_new_backup_channel(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), msg.initiator);
        if (command_return != SGX_SUCCESS || ecall_return != 0) {
            error("ecall_create_new_backup_channel");
        }
    } else {
        int command_return = ecall_create_new_channel(global_eid, &ecall_return, channel_id.c_str(), channel_id.length(), msg.initiator);
        if (command_return != SGX_SUCCESS || ecall_return == REQUEST_CRASHED) {
            error("ecall_create_new_channel");
        }
    }

    if (ecall_return == REQUEST_FAILED) {
	printf("Failed to create new channel! Check arguments and try again?");        
        send_ack(client_fd, OP_LOCAL_ACK, "failed to create new channel");
        return;
    }

    ChannelState *channel_state = create_channel_state();
    initialise_channel_state(channel_state, msg.initiator);
    channel_state->is_backup_channel = is_backup;
    associate_channel_state(channel_id, channel_state);

    if (channel_state->is_initiator) {
        channel_state->connection.remote_port = msg.remote_port;
        channel_state->connection.remote_host_len = msg.remote_host_len;
        memcpy((char *) channel_state->connection.remote_host, msg.remote_host, channel_state->connection.remote_host_len);
    }

    // save local sockfd so we can ack when the channel has been created
    channel_state->connection.local_sockfd = client_fd;

    if (channel_state->is_initiator) {
        channel_state->connection.remote_sockfd = connect_to_socket(std::string(channel_state->connection.remote_host, channel_state->connection.remote_host_len).c_str(), channel_state->connection.remote_port);

        // Let remote know we generated a new channel id that should be shared between us
        send_message(OP_REMOTE_CHANNEL_ID_GENERATED, (char *) channel_id.c_str(), &is_backup, sizeof(bool), channel_state->connection.remote_sockfd);

        perform_handshake(channel_state);
        register_new_connection(channel_state->connection.remote_sockfd);
    }
}

static void process_packet(char* packet, int pktlen, int client_fd) {
    bool islocalhost = connections[client_fd].islocalhost;
    char operation = packet[MSG_LEN_BYTES]; 
    char channel_id[CHANNEL_ID_LEN];
    int msglen = pktlen - MSG_LEN_BYTES; // remove pkt size and operation
    //log_debug("Processing packet number: %d, length: %d, and is from local host? %d", operation, pktlen, islocalhost);

    // process bitcoin send and receive messages
    if (islocalhost && (operation == OP_LOCAL_SEND)) { // received local send
        send(&packet[MSG_LEN_BYTES], client_fd);

    } else if (operation == OP_REMOTE_SEND) { // received a send request
        process_send_request(&packet[MSG_LEN_BYTES], msglen, client_fd);
    
    } else if (operation == OP_REMOTE_SEND_ACK) { // received a send ack from the remote
        process_send_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA) { // received remote update channel balance data
        process_update_channel_balance(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_UPDATE_CHANNEL_BALANCE_DATA_ACK) { // received remote update channel balance data ack
        process_update_channel_balance_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_BALANCE)) { // received local balance
        balance(&packet[MSG_LEN_BYTES], client_fd);

    // process local primary commands 
    } else if (islocalhost && (operation == OP_LOCAL_PRIMARY)) { // received local primary
        primary(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_TEECHAIN_SETUP_DEPOSITS)) { // received local teechain setup
        setup_deposits(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_TEECHAIN_DEPOSITS_MADE)) { // received local deposits made
        deposits_made(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_VERIFY_DEPOSITS)) { // received local established
        verify_deposits(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_CREATE)) { // received local create
        create(false, &packet[MSG_LEN_BYTES], client_fd);

    // process local backup commands
    } else if (islocalhost && (operation == OP_LOCAL_BACKUP)) { // received local backup
        backup(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_ADD_BACKUP)) { // received local add backup
        create(true, &packet[MSG_LEN_BYTES], client_fd);

    } else if (operation == OP_REMOTE_BACKUP_DATA) { // received remote backup data
        process_backup_data(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_BACKUP_DATA_ACK) { // received backup ack from other enclave
        process_backup_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_REMOVE_BACKUP)) { // received local remove backup
        remove_backup(&packet[MSG_LEN_BYTES], client_fd);

    } else if (operation == OP_REMOTE_REMOVE_BACKUP) { // received remove request for backup from other enclave
        process_remove_backup(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_REMOVE_BACKUP_ACK) { // received remove ack for backup from other enclave
        process_remove_backup_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    // process local shutdown and settle commands
    } else if (islocalhost && (operation == OP_LOCAL_SETTLE)) { // received local settle
        settle(&packet[MSG_LEN_BYTES],client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_RETURN_UNUSED)) { // received local shutdown
        return_unused_deposits(&packet[MSG_LEN_BYTES],client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_SHUTDOWN)) { // received local shutdown
        shutdown(&packet[MSG_LEN_BYTES],client_fd);

    // process channel create messages (includes remote attestation and key exchange messages)
    } else if (operation == OP_REMOTE_CHANNEL_CREATE_DATA) { // received encrypted channel create data from other enclave
        process_channel_create_data(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_CHANNEL_ID_GENERATED) { // received channel id generated message from other enclave
        process_channel_id_generated(&packet[MSG_LEN_BYTES], msglen);

    } else if (operation == OP_REMOTE_RA_MSG0) { // received msg0 from other enclave
        process_ra_msg0(&packet[MSG_LEN_BYTES], msglen);

    } else if (operation == OP_REMOTE_RA_MSG1) { // received msg1 from other enclave
        process_ra_msg1(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_RA_MSG2) { // received msg2 from other enclave
        process_ra_msg2(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_RA_MSG3) { // received msg3 from other enclave
        process_ra_msg3(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_RA_RESULT) { // received result from other enclave
        process_ra_result(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_VERIFY_DEPOSITS_ACK) { // received an established ack from the remote
        process_verify_deposits_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    // process deposit commands
    } else if (islocalhost && (operation == OP_LOCAL_TEECHAIN_DEPOSIT_ADD)) { // received local teechain deposit add request
        add_deposit(&packet[MSG_LEN_BYTES], client_fd);

    } else if (islocalhost && (operation == OP_LOCAL_TEECHAIN_DEPOSIT_REMOVE)) { // received local teechain deposit remove request
        remove_deposit(&packet[MSG_LEN_BYTES], client_fd);

    } else if (operation == OP_REMOTE_TEECHAIN_DEPOSIT_ADD) { // received deposit add request from other enclave
        process_deposit_add(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_TEECHAIN_DEPOSIT_ADD_ACK) { // received deposit add ack from other enclave
        process_deposit_add_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE) { // received deposit add request from other enclave
        process_deposit_remove(&packet[MSG_LEN_BYTES], msglen, client_fd);

    } else if (operation == OP_REMOTE_TEECHAIN_DEPOSIT_REMOVE_ACK) { // received deposit add ack from other enclave
        process_deposit_remove_ack(&packet[MSG_LEN_BYTES], msglen, client_fd);

    // invalid packet sent
    } else {
        log_debug("Invalid Packet");
    }
}

static void process_events(int epoll_wait_res, int server) {
    for (int index = 0; index < epoll_wait_res; index++) {
        int client_fd = events[index].data.fd;
        if (client_fd == server) { // connection arrived on the server port
            accept_new_connection(server);
            continue;
        }

        if (events[index].events & EPOLLIN)  {
            char buf[MAX_MESSAGE_RESPONSE_LENGTH];
            int num_bytes = recv(client_fd, buf, sizeof(buf), 0);

            if (num_bytes <= 0) {
                close_socket(client_fd);
                continue;
            }

            connections[client_fd].input.insert(connections[client_fd].input.end(), &buf[0], &buf[num_bytes]);
            while (connections[client_fd].input.size() > MSG_LEN_BYTES) {
                long pktlen = *((long*) connections[client_fd].input.data());
                if (pktlen <= connections[client_fd].input.size()) { // got an entire packet

                    process_packet(connections[client_fd].input.data(), pktlen, client_fd);
                    // remove processed packet from input
                    connections[client_fd].input.erase(connections[client_fd].input.begin(), connections[client_fd].input.begin() + pktlen);
                } else {
                    break;
                }
            }
        }
    }
}

// this creates a teechain enclave and the untrusted I/O thread that communicates with the enclave.
// this ensemble is known as the "mothership"
void ghost(int port) {
    log_debug("Setting up ghost on localhost:%d ...", port);
    int optval = 1;
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) {
        error("socket_create");
    }

    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0) {
        error("setsockopt");
    }

    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    serveraddr.sin_port = htons(port);
    memset(&(serveraddr.sin_zero), '\0', 8);

    if (bind(server, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in)) < 0) {
        error("bind");
    }

    if (listen(server, MAX_BACKLOG) < 0) {
        error("listen");
    }

    // initialize global epoll_fd
    epoll_fd = epoll_create(MAX_CONNECTIONS);
    if (epoll_fd < 0) {
        error("epoll_create");
    }

    event.events = EPOLLIN | EPOLLHUP;
    event.data.fd = server;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server, &event) < 0) {
        error("epoll_ctl");
    }

    log_debug("%s", "Setting up the enclave...");
    ghost_enclave();
    print("Enclave created.");

    while (true) { // wait for socket events
        int res = epoll_wait(epoll_fd, events, MAX_CONNECTIONS, -1);
        if (res < 0) {
            error("epoll_wait");
        }
        process_events(res, server);
    }
}
