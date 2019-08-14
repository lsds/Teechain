#ifndef _STATE_H_
#define _STATE_H_

#include <string>
#include <map>
#include <set>

#include "service_provider.h"

// TODO: update enclave state checks for ghost, primary, backups and also multiple channels
// enclave state machine
// protects enclave (can only ascend through enclaveState, 1 state at a time)
// must choose between primary or backup
// if primary, must choose between initiator, or non initiator when ascending
enum TeechanState {
	Ghost, // ghost enclave created

	Backup, // enclave is backup -- never changes state from this

	Primary, // enclave is assigned primary
	WaitingForFunds, // enclave is waiting for funding
	Funded, // enclave has been funded
};

// Represents a deposit (or unspent output) in the Setup Transaction
class Deposit {
    public:
        bool is_spent;

        std::string bitcoin_address;
        std::string public_key;
        std::string private_key;

        std::string script;

        std::string txid;
        unsigned long long tx_index;
        unsigned long long deposit_amount;

};

// Setup transaction state for the on-chain setup transaction.
// Vectors that store the deposit amounts, bitcoin addresses, public
// and private keys are all ordered (e.g. to find the private key
// of a public key at vector index i, you just look up the same index
// in the private key vector)
// The deposit IDs are the index where they are stored in the vector.
class SetupTransaction {
    public:
        // Input transaction information and keys to construct the setup transaction
        std::string public_key;
        std::string private_key;
        std::string utxo_hash;
        unsigned long long utxo_index;
        std::string utxo_script;

        // Setup transaction to place onto the blockchain
        std::string setup_transaction_hash;

        // Assignments from deposit indexes to deposits
        std::map<unsigned long long, Deposit> deposit_ids_to_deposits;

        // Assignments from deposit indexes to channel IDs
        std::map<unsigned long long, std::string> deposit_ids_to_channels;

        // Bitcoin address to pay when a channel is closed
        std::string my_address;

        // Bitcoin miner fee to pay whenver I generate a transaction
        unsigned long long miner_fee;
};

extern TeechanState teechain_state;
bool check_state(TeechanState state);

#endif
