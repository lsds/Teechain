#!/bin/bash
set -e

# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

ALICE_PORT=10001
BOB_PORT=10002

ALICE_LOG=bin/testnet/test/alice.txt
BOB_LOG=bin/testnet/test/bob.txt

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
echo "${bold}Starting two ghost teechain enclaves...${reset}"

echo "${bold}Spawning enclave ALICE listening on port $ALICE_PORT in $ALICE_LOG ${reset}"
./teechain ghost -d -p $ALICE_PORT > $ALICE_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave BOB listening on port $BOB_PORT in $BOB_LOG ${reset}"
./teechain ghost -d -p $BOB_PORT > $BOB_LOG 2>&1 &
sleep 1

echo -n "${red}Waiting until enclaves are initialized ...!${reset}"
for u in alice bob; do  #TODO: generalize to multiple parties (not just 4)
    while [ "$(grep -a 'Enclave created' bin/testnet/test/${u}.txt | wc -l)" -eq 0 ]; do
        sleep 0.1
        echo -n "."
    done
done

# Create primaries
./teechain primary -p $ALICE_PORT
./teechain primary -p $BOB_PORT

# Setup up primaries with number of deposits
./teechain setup_deposits 2 -p $ALICE_PORT
./teechain setup_deposits 1 -p $BOB_PORT

# Deposits made
./teechain deposits_made mmY6ijr6uLP3DdRFC4nwL23HSKsH2xgy74 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 0 100 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 1000 -p $ALICE_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feC 0 100 -p $BOB_PORT

# Create and establish a channel between Alice and Bob
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $ALICE_PORT # Initiator

sleep 2

# Extract the channel id for the channel created
CHANNEL_1=$(grep "Channel ID:" $ALICE_LOG | awk '{print $3}')

# Verified the setup transactions are in the blockchain
./teechain verify_deposits $CHANNEL_1 -p $BOB_PORT &
./teechain verify_deposits $CHANNEL_1 -p $ALICE_PORT

sleep 2

# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 0, remote balance is: 0"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Alice and Bob add deposits to their channels now
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT

# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 100, remote balance is: 100"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Send from Bob to Alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT

# Alice check balance after
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "My balance is: 101, remote balance is: 99"; then
    echo "Alice's balance check failed after send!"; exit 1;
fi

# Send from Bob to Alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT

# Bob check balance
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 98, remote balance is: 102"; then
    echo "Bob's balance check failed after second send!"; exit 1;
fi

# Send from Alice to Bob
./teechain send $CHANNEL_1 50 -p $ALICE_PORT

# Bob check balance
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep -q "My balance is: 148, remote balance is: 52"; then
    echo "Bob's balance check failed after alice's send!"; exit 1;
fi

# Settle and shutdown
./teechain settle_channel $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep -q "0100000002ea0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffffec0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffff0234000000000000001976a9144208343a1b63978713f830666ce6d5ab7fa1784488ac94000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac00000000"; then
    echo "Alice's channel wasn't settled!"; exit 1;
fi

# Alice decides to get her unused deposit out
./teechain shutdown -p $ALICE_PORT
if ! tail -n 40 $ALICE_LOG | grep -q "0100000001eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0100000000ffffffff0109030000000000001976a9144208343a1b63978713f830666ce6d5ab7fa1784488ac00000000"; then
    echo "Alice's unused deposits weren't returned!"; exit 1;
fi
if ! tail -n 20 $ALICE_LOG | grep -q "0100000002ea0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffffec0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffff0234000000000000001976a9144208343a1b63978713f830666ce6d5ab7fa1784488ac94000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac00000000"; then
    echo "Alice's channel wasn't settled!"; exit 1;
fi

popd # return to bin directory

../kill.sh
echo "${bold}Looks like the test passed!${reset}"
