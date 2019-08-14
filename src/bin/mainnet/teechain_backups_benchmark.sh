#!/bin/bash
set -e

# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

ALICE_PORT=10001
ALICE_BACKUP_PORT_1=20001
ALICE_BACKUP_PORT_2=30001

BOB_PORT=10002
BOB_BACKUP_PORT_1=20002

ALICE_LOG=bin/mainnet/test/alice.txt
ALICE_BACKUP_LOG_1=bin/mainnet/test/alice_backup_1.txt
ALICE_BACKUP_LOG_2=bin/mainnet/test/alice_backup_2.txt

BOB_LOG=bin/mainnet/test/bob.txt
BOB_BACKUP_LOG_1=bin/mainnet/test/bob_backup_1.txt

if test -d bin; then cd bin; fi

echo "${bold}Mounting a RAM disk for server output in test directory!${reset}"
if mountpoint -q -- "test"; then
    sudo umount test
fi

rm -r test | true # in case this is the first time being run
mkdir test && sudo mount -t tmpfs -o size=5000m tmpfs test

# Source Intel Libraries
source /opt/intel/sgxsdk/environment

pushd ../../ # go to source directory
echo "${bold}Starting the ghost teechain enclaves...${reset}"

echo "${bold}Spawning enclave ALICE listening on port $ALICE_PORT in $ALICE_LOG ${reset}"
./teechain ghost -b -p $ALICE_PORT > $ALICE_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave ALICE_BACKUP_1 listening on port $ALICE_BACKUP_1 in $ALICE_BACKUP_LOG_1 ${reset}"
./teechain ghost -b -p $ALICE_BACKUP_PORT_1 > $ALICE_BACKUP_LOG_1 2>&1 &
sleep 1

echo "${bold}Spawning enclave ALICE_BACKUP_2 listening on port $ALICE_BACKUP_2 in $ALICE_BACKUP_LOG_2 ${reset}"
./teechain ghost -b -p $ALICE_BACKUP_PORT_2 > $ALICE_BACKUP_LOG_2 2>&1 &
sleep 1

echo "${bold}Spawning enclave BOB listening on port $BOB_PORT in $BOB_LOG ${reset}"
./teechain ghost -b -p $BOB_PORT > $BOB_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave BOB_BACKUP_1 listening on port $BOB_BACKUP_1 in $BOB_BACKUP_LOG_1 ${reset}"
./teechain ghost -b -p $BOB_BACKUP_PORT_1 > $BOB_BACKUP_LOG_1 2>&1 &
sleep 1

echo -n "${red}Waiting until enclaves are initialized ...!${reset}"
for u in alice alice_backup_1 alice_backup_2 bob bob_backup_1; do
    while [ "$(grep -a 'Enclave created' bin/mainnet/test/${u}.txt | wc -l)" -eq 0 ]; do
        sleep 0.1
        echo -n "."
    done
done

# Create primaries and backups
./teechain primary -p $ALICE_PORT
./teechain backup -p $ALICE_BACKUP_PORT_1
./teechain backup -p $ALICE_BACKUP_PORT_2

./teechain primary -p $BOB_PORT
./teechain backup -p $BOB_BACKUP_PORT_1

# Setup up primaries with number of deposits
./teechain setup_deposits 1 -p $ALICE_PORT
./teechain setup_deposits 1 -p $BOB_PORT

# Deposits made
./teechain deposits_made 1PxpP8fCsdjVrS187fP2byc5uYap3fA7j2 1 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 0 1000002 -p $ALICE_PORT
./teechain deposits_made 1NqY7EC7Y5oZSMHos3CJxv1Z69BdkLZvWy 1 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 1 -p $BOB_PORT

# Assign backup to Alice
./teechain add_backup -p $ALICE_PORT &
sleep 1
./teechain add_backup -i -r 127.0.0.1:$ALICE_PORT -p $ALICE_BACKUP_PORT_1

sleep 2

# Extract the channel id for the channel created
ALICE_BACKUP_CHANNEL_1=$(grep "Backup Channel ID:" $ALICE_BACKUP_LOG_1 | awk '{print $4}')
echo "Backup Channel 1 ID is $ALICE_BACKUP_CHANNEL_1"

# Assign another backup to alice chain
./teechain add_backup -p $ALICE_BACKUP_PORT_1 &
sleep 1
./teechain add_backup -i -r 127.0.0.1:$ALICE_BACKUP_PORT_1 -p $ALICE_BACKUP_PORT_2

sleep 2

# Extract the channel id for the channel created
ALICE_BACKUP_CHANNEL_2=$(grep "Channel ID:" $ALICE_BACKUP_LOG_2 | awk '{print $4}')
echo "Backup Channel 2 ID is $ALICE_BACKUP_CHANNEL_2"

# Assign backup to Bob
./teechain add_backup -p $BOB_PORT &
sleep 1
./teechain add_backup -i -r 127.0.0.1:$BOB_PORT -p $BOB_BACKUP_PORT_1

sleep 2

# Extract the channel id for the channel created
BOB_BACKUP_CHANNEL_1=$(grep "Backup Channel ID:" $BOB_BACKUP_LOG_1 | awk '{print $4}')
echo "Backup Channel 3 ID is $BOB_BACKUP_CHANNEL_1"

# Create and establish a channel between Alice and Bob
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $ALICE_PORT # Initiator

sleep 2

# Extract the channel id for the channel created
CHANNEL_1=$(tail -n 7 $ALICE_LOG | grep "Channel ID:" | awk '{print $3}')
echo "Channel 1 ID is $CHANNEL_1"


# Verified the setup transactions are in the blockchain
./teechain verify_deposits $CHANNEL_1 -p $BOB_PORT &
./teechain verify_deposits $CHANNEL_1 -p $ALICE_PORT

sleep 2

# Alice and Bob add deposits to their channels now
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT

# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep "My balance is: 1000002, remote balance is: 1"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

echo "Alice is sending 50,000 satoshi, 1 at a time to Bob!"
./teechain -b benchmark $CHANNEL_1 50000 -p $ALICE_PORT

# Alice check balance after
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep "My balance is: 950002, remote balance is: 50001"; then
    echo "Alice's balance check failed after send!"; exit 1;
fi


popd # return to bin directory

../kill.sh
echo "${bold}Looks like the test passed!${reset}"
