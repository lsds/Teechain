#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <vector>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#include "network.h"
#include "channel.h"
#include "command_line_interface.h"
#include "ocalls.h"

// enclave file
#define TOKEN_FILENAME   "enclave.token"
#define TEECHAN_SEC_FILENAME "teechain.signed.so"
#define MAX_PATH FILENAME_MAX

// ecall constants
#define MAX_ECALL_USER_OUTPUT 500  // 0.5 KB is max ecall return length
#define MAX_ECALL_SEND_RETURN_LENGTH 10000 // 10 KB is max message length across network
#define MAX_ECALL_RETURN_LENGTH 100000 // 100 KB is max message length across network

extern int epoll_fd;

// functions to export
void ghost(int port);
int initialize_enclave();

int connect_to_socket(std::string socket_hostname, int socket_port);
void send_on_socket(char* msg, long msglen, int sockfd);
void read_from_socket(int sockfd, char* buf, long length);

void generate_and_send_encrypted_backup_state(ChannelState *channel_state);
void generate_and_send_encrypted_deposit_data(ChannelState *channel_state);
void perform_handshake(ChannelState *channel_state);

void send_message(uint32_t operation, char *channel_id, void* msg_pointer, int msg_size, int sockfd);
void send_encrypted_message(uint32_t operation, char* channel_id, char* encrypted_data, int encrypted_data_len, char* p_gcm_mac, int sockfd);
void send_ack(int client_fd, int response, const char *info_msg);

void register_new_connection(int conn_sock);

void get_user_output_for_channel(std::string channel_id, char* user_output);
void shutdown_enclave(char* user_output);

#endif /* !_APP_H_ */
