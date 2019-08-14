#!/bin/bash
set -e

# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

ALICE_PORT=10001
BOB_PORT=10002
CAROL_PORT=10003

ALICE_LOG=bin/testnet/test/alice.txt
BOB_LOG=bin/testnet/test/bob.txt
CAROL_LOG=bin/testnet/test/carol.txt

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
echo "${bold}Starting ghost teechain enclaves...${reset}"

echo "${bold}Spawning enclave ALICE listening on port $ALICE_PORT in $ALICE_LOG ${reset}"
./teechain ghost -d -p $ALICE_PORT > $ALICE_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave BOB listening on port $BOB_PORT in $BOB_LOG ${reset}"
./teechain ghost -d -p $BOB_PORT > $BOB_LOG 2>&1 &
sleep 1

echo "${bold}Spawning enclave CAROL listening on port $CAROL_PORT in $CAROL_LOG ${reset}"
./teechain ghost -d -p $CAROL_PORT > $CAROL_LOG 2>&1 &
sleep 1

echo -n "${red}Waiting until enclaves are initialized ...!${reset}"
for u in alice bob carol; do  #TODO: generalize to multiple parties (not just 4)
    while [ "$(grep -a 'Enclave created' bin/testnet/test/${u}.txt | wc -l)" -eq 0 ]; do
        sleep 0.1
        echo -n "."
    done
done

# Create primaries
./teechain primary -p $ALICE_PORT
./teechain primary -p $BOB_PORT
./teechain primary -p $CAROL_PORT

# Setup up primaries with number of deposits
./teechain setup_deposits 2 -p $ALICE_PORT
./teechain setup_deposits 3 -p $BOB_PORT
./teechain setup_deposits 2 -p $CAROL_PORT

# Deposits made
./teechain deposits_made mmY6ijr6uLP3DdRFC4nwL23HSKsH2xgy74 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 1 10 -p $ALICE_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 3 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 2 4 -p $BOB_PORT
#./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 2 10 76a914c0cbe7ba8f82ef38aed886fba742942a9893497788aa 20 76a914c0cbe7ba8f82ef38aed886fba742942a9893497788ab -p $CAROL_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 10 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 20 -p $CAROL_PORT

# Create and establish a channel between Alice and Bob
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $ALICE_PORT # Initiator

sleep 2

# Extract the channel id for the channel created
CHANNEL_1=$(grep "Channel ID:" $ALICE_LOG | awk '{print $3}')

./teechain verify_deposits $CHANNEL_1 -p $BOB_PORT &
./teechain verify_deposits $CHANNEL_1 -p $ALICE_PORT

sleep 2

# Create and establish a channel between Bob and Carol
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $CAROL_PORT # Initiator

# Extract the channel id for the channel created
CHANNEL_2=$(grep "Channel ID:" $CAROL_LOG | awk '{print $3}')

sleep 2

./teechain verify_deposits $CHANNEL_2 -p $BOB_PORT &
./teechain verify_deposits $CHANNEL_2 -p $CAROL_PORT

# Alice, Bob and Carol now add deposits to their channels
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT

./teechain add_deposit $CHANNEL_2 1 -p $BOB_PORT
./teechain add_deposit $CHANNEL_2 1 -p $CAROL_PORT


# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep "My balance is: 1, remote balance is: 1"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Bob check balance with carol matches expected
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 2, remote balance is: 20"; then
    echo "Bob's balance check failed on channel setup!"; exit 1;
fi

# Send from Bob to Alice
./teechain send $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep "My balance is: 2, remote balance is: 0"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Send from Bob to Carol
./teechain send $CHANNEL_2 1 -p $BOB_PORT
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 1, remote balance is: 21"; then
    echo "Bob's balance check failed on channel setup!"; exit 1;
fi

# Try to add already used Deposit
./teechain add_deposit $CHANNEL_1 1 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 0, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob tried to use an already added deposit!"

# Add unused deposit
./teechain add_deposit $CHANNEL_1 2 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 4, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob added an unused deposit to channel with Alice!"

# Remove invalid deposit index
./teechain remove_deposit $CHANNEL_1 3 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 4, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob tried to remove an invalid deposit index!"

# Remove valid deposit
./teechain remove_deposit $CHANNEL_1 0 -p $BOB_PORT
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 3, remote balance is: 2"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob removed deposit 0!"

# Add just removed deposit to another channel
./teechain add_deposit $CHANNEL_2 0 -p $BOB_PORT
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 2, remote balance is: 21"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob added deposit 0 to channel 2!"

# Do some arbitary sends back and forth (balance in channel 1: 2-3, in channel 2: 2-21)
./teechain send $CHANNEL_1 1 -p $ALICE_PORT # 1-4
./teechain send $CHANNEL_1 1 -p $ALICE_PORT # 0-5
./teechain send $CHANNEL_2 1 -p $BOB_PORT # 1-22
./teechain send $CHANNEL_1 1 -p $BOB_PORT # 1-4
./teechain send $CHANNEL_2 5 -p $CAROL_PORT # 6-17

# Check all balances across nodes are correct
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 2 $ALICE_LOG | grep "My balance is: 1, remote balance is: 4"; then
    echo "Alice's balance check failed!"; exit 1;
fi
./teechain balance $CHANNEL_1 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 4, remote balance is: 1"; then
    echo "Bob's balance check failed!"; exit 1;
fi
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 2 $BOB_LOG | grep "My balance is: 6, remote balance is: 17"; then
    echo "Bob's balance check failed!"; exit 1;
fi
./teechain balance $CHANNEL_2 -p $CAROL_PORT
if ! tail -n 2 $CAROL_LOG | grep "My balance is: 17, remote balance is: 6"; then
    echo "Bob's balance check failed!"; exit 1;
fi

# Alice Settle and shutdown (one unused deposit)
./teechain settle_channel $CHANNEL_1 -p $ALICE_PORT
./teechain shutdown -p $ALICE_PORT

# Bob Settle and shutdown (no unused deposit)
./teechain settle_channel $CHANNEL_1 -p $BOB_PORT
./teechain return_unused_deposits -p $BOB_PORT
./teechain settle_channel $CHANNEL_2 -p $BOB_PORT
./teechain shutdown -p $BOB_PORT

# Carol Settle and shutdown (one unused deposit)
./teechain settle_channel $CHANNEL_2 -p $CAROL_PORT
./teechain shutdown -p $CAROL_PORT

popd # return to bin directory

../kill.sh
echo "${bold}Looks like the test passed!${reset}"
