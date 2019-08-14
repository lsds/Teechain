#ifndef _BACKUPS_H_
#define _BACKUPS_H_

// Functions to export:
void backup(char *data, int client_fd);
void generate_and_send_encrypted_backup_state(ChannelState *channel_state);
void process_backup_data(char* data, int data_len, int sockfd);
void process_update_channel_balance(char* data, int data_len, int sockfd);
void process_remove_backup(char* data, int data_len, int sockfd);
void process_remove_backup_ack(char* data, int data_len, int sockfd);
void process_backup_ack(char* data, int data_len, int sockfd);
void remove_backup(char* data, int client_fd);
void add_backup(char* data, int client_fd);

#endif /* _BACKUPS_H */

