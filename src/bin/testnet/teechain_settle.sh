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
./teechain setup_deposits 4 -p $BOB_PORT
./teechain setup_deposits 2 -p $CAROL_PORT

# Deposits made
./teechain deposits_made mmY6ijr6uLP3DdRFC4nwL23HSKsH2xgy74 100 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feA 1 10 -p $ALICE_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 4 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 1 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 2 4 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 3 8 -p $BOB_PORT
./teechain deposits_made my6NJU1T6gL5f3TfmSPN4idUytdCQHTmsU 1 2 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 0 10 edec34c9bb3a4395cd8d1e9300725f537235d8a058fc6a7ae519003b64fd0feB 1 20 -p $CAROL_PORT

# Create and establish a channel between Alice and Bob
./teechain create_channel -p $BOB_PORT &
sleep 1
./teechain create_channel -i -r 127.0.0.1:$BOB_PORT -p $ALICE_PORT # Initiator


# Extract the channel id for the channel created
CHANNEL_1=$(grep "Channel ID:" $ALICE_LOG | awk '{print $3}')

sleep 2

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

# Add funds to all channels
./teechain add_deposit $CHANNEL_1 0 -p $ALICE_PORT
./teechain add_deposit $CHANNEL_1 0 -p $BOB_PORT

./teechain add_deposit $CHANNEL_2 1 -p $BOB_PORT
./teechain add_deposit $CHANNEL_2 1 -p $CAROL_PORT


# Alice check balance matches expected
./teechain balance $CHANNEL_1 -p $ALICE_PORT
if ! tail -n 3 $ALICE_LOG | grep -q "My balance is: 1, remote balance is: 1"; then
    echo "Alice's balance check failed on channel setup!"; exit 1;
fi

# Bob check balance with carol matches expected
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "My balance is: 2, remote balance is: 20"; then
    echo "Bob's balance check failed on channel setup!"; exit 1;
fi

# Bob settle channel 1 to mark deposits 0 spent
./teechain settle_channel $CHANNEL_1 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "has settled your channel"; then
    echo "Failed to settle Bob's channel 1!"; exit 1;
fi

# Bob try to add deposit 0 to channel 2: should fail
./teechain add_deposit $CHANNEL_2 0 -p $BOB_PORT
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "My balance is: 2, remote balance is: 20"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob tried to use an already added deposit!"

# Bob try to add deposit 2 to channel 2: should work
./teechain add_deposit $CHANNEL_2 2 -p $BOB_PORT
./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "My balance is: 6, remote balance is: 20"; then
    echo "Bob's balance check failed!"; exit 1;
fi
echo "Bob added deposit 2 to channel 2!"

# Bob return unused deposits: should return deposit index 3
./teechain return_unused_deposits -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "0100000001eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0300000000ffffffff0108000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac00000000"; then
    echo "Failed to return deposit index 3!"; exit 1;
fi
echo "Bob returned his unused deposits!"

./teechain remove_deposit $CHANNEL_2 2 -p $BOB_PORT
echo "Bob removed deposit 2 from channel 2!"

# Bob removes deposit 2 from channel 2, making it unused
./teechain return_unused_deposits -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "0100000001eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0200000000ffffffff0104000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac00000000"; then
    echo "Failed to return deposit index 2!"; exit 1;
fi
echo "Bob returned his unused deposits again!"

./teechain balance $CHANNEL_2 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "My balance is: 2, remote balance is: 20"; then
    echo "Bob's balance check failed!"; exit 1;
fi

# Bob settle channel 1
./teechain settle_channel $CHANNEL_1 -p $BOB_PORT
if ! tail -n 3 $BOB_LOG | grep -q "0100000002eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffffea0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffff0201000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac01000000000000001976a9144208343a1b63978713f830666ce6d5ab7fa1784488ac00000000"; then
    echo "Failed to settle Bob's channel 1!"; exit 1;
fi
echo "Bob settled his channel 1"

# Bob shutdown: should return no unused, and settle both channels
./teechain shutdown -p $BOB_PORT
if ! tail -n 40 $BOB_LOG | grep -q "0100000002eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffffea0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0000000000ffffffff0201000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac01000000000000001976a9144208343a1b63978713f830666ce6d5ab7fa1784488ac00000000"; then
    echo "Failed to settle Bob's channel 1 as part of shutdown"; exit 1;
fi
if ! tail -n 40 $BOB_LOG | grep -q "0100000002eb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0100000000ffffffffeb0ffd643b0019e57a6afc58a0d83572535f7200931e8dcd95433abbc934eced0100000000ffffffff0116000000000000001976a914c0cbe7ba8f82ef38aed886fba742942a9893497788ac00000000"; then
    echo "Failed to settle Bob's channel 2 as part of shutdown"; exit 1;
fi

popd # return to bin directory

echo "${bold}Looks like the test passed!${reset}"
../kill.sh
