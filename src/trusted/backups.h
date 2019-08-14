#ifndef _BACKUPS_H_
#define _BACKUPS_H_

#include "network.h"

extern bool write_to_stable_storage;
extern std::string prev_backup_channel_id;
extern std::string next_backup_channel_id;

bool have_backup();
void increment_monotonic_counter_and_write_state_to_storage(std::string channel_id);
int send_backup_store_request(std::string blocked_channel_id, struct BackupRequest blocked_request, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
int send_update_channel_balance_request(std::string blocked_channel_id, std::string nonce, bool any_failures, char* encrypted_data_out, int* encrypted_data_out_len, char* p_gcm_mac, char *next_channel_id_to_send_on, int* send_action);
void print_backup_state(struct BackupEnclaveStateMsg msg);

#endif /* _BACKUPS_H_ */
