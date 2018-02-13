# Teechain: Scalable Blockchain Payments using Trusted Execution Environments.

Teechain, an off-chain payment protocol that utilizes trusted execution environments (TEEs) to perform secure, efficient and scalable fund transfers on top of a blockchain.

## Downloading the Teechain binaries

To download the Teechain binaries, follow the download link at [teechain.network](https://teechain.network). This will require agreeing to a disclaimer before the files can be downloaded. The resulting download will be in the form of a tarball, and can be uncompressed using the command: ``tar xvzf teechain-alpha.tar.gz``.

## What is this?

This repository contains instructions, binaries, and help content for the alpha release of the Teechain network. For this release we are providing pre-compiled binaries that can create and operate payment channels between users for the Bitcoin network. Our release targets Intel SGX as the trusted execution environment, and it includes separate binaries: (i) simulation binaries that can be run without requiring any special hardware; and (ii) debug Intel SGX binaries that can be run within an Intel SGX enclave.

The binaries available in this release support the Bitcoin testnet and the Bitcoin mainnet. We are not responsible for any loss of funds, or any damages that might be incurred by using our software. Given the early nature of this release, we do not recommend placing real money in Teechain operated channels. This software is to be taken as a demonstration of Teechain's capabilities. Use at your own risk.

The Intel SGX binaries provided here are debug binaries. This means that the security properties and access control mechanisms provided by Intel SGX enclaves are not enforced when running these binaries. If you would like access to our production, signed, Intel SGX binaries (that do run securely within an enclave) please contact us.

## What do I need to use Teechain?

To begin experimenting with Teechain and to run the simulation binaries, all you will need is to install the Intel SGX SDK. An Intel SGX enabled processor is not required.

To run Teechain in production mode, you'll need to install the Intel SGX SDK, PSW, and the SGX Driver, as well as have access to an SGX-enabled machine.

Follow the installation instructions below to get started. To see whether or not you have an Intel SGX enabled processor, follow the instructions [here](https://github.com/ayeks/SGX-hardware).


## What features are included in this release?

For this release, we are providing the ability to: (i) fund Teechain nodes using Bitcoin transactions; (ii) create secure payment channels between endpoints (without requiring access to the Bitcoin blockchain); (iii) add and remove funds from payment channels dynamically; (iv) create and assign backup Teechain nodes to replicate Teechain state and prevent fund loss; and (v) terminate individual channels and return funds held by the enclave.

What we are not providing in this release is: (i) the ability to route funds across multiple channels; or (ii) the ability to write
state to stable storage through the use of monotonic counters. Although both of these features are in fact already implemented, we will only be making them available in a future release.

## Teechain requirements

To install and run Teechain, we recommend using Ubuntu 16.04 LTS. Teechain might work on other versions of Linux, however, we are not providing official support for these at present. There is also currently no support for Windows.

1. First, you will need to install the Intel SGX SDK for Linux, which can be found [here](https://github.com/intel/linux-sgx). We recommend installing [version 2.1](https://github.com/intel/linux-sgx/releases/tag/sgx_2.1). 

Note, when installing the SDK and being asked where to install the files, we recommend specifying ``/opt/intel/``, as this is where our scripts look for the environment variables.

2. To run production enclaves, you will need an Intel SGX enabled machine and to install the SGX PSW (instructions can be found on the Linux SGX SDK GitHub [here](https://github.com/intel/linux-sgx)). You will also need to install the Intel SGX Driver [here](https://github.com/intel/linux-sgx-driver).
For both the PSW and the Driver we recommend installing version 2.1 ([here](https://github.com/intel/linux-sgx/releases/tag/sgx_2.1) and [here](https://github.com/intel/linux-sgx-driver/releases/tag/sgx_driver_2.1)), and installing to the path ``/opt/intel/``.

3. Ensure that you can run some of the Intel SGX provided sample applications first, before trying to run Teechain in simulation or hardware mode. Assuming the SDK was installed to ``/opt/intel/``, the example applications should be in ``/opt/intel/sgxsdk/SampleCode/``

4. Finally, Teechain requires the curl development libraries, so also install those by running: ``sudo apt-get install libcurl-dev``.

## Checking Teechain Works/Running Teechain Examples

This distribution includes binaries and example test scripts that execute various features of Teechain payment channels. To check that Teechain is working, and has all the required components, we can execute some tests:

1. To check that Teechain is executing correctly, first run ``./prepare_sim_mode.sh`` in ``test_scripts/testnet/``. This will copy the testnet simulation binaries to the root of the repository.

2. Next, execute any one of the test scripts in ``test_scripts/testnet/``, such as ``./teechain_send.sh``, to check that things are working. ``./teechain_send.sh`` will setup a simple channel between two endpoints on the local machine, add deposits to those channels, send some payments, check balances of the channel, terminate the channel, and return any unused deposits held by the enclave. The output should indicate a successful run. 

Assuming everything executes correctly, you will have succesfully operated a Teechain payment channel in simulation mode for the testnet. Note: no real testnet bitcoins would have been exchanged in this test script because the transactions presented to the enclaves are not legitimate transactions that have been placed in the testnet blockchain. To actually operate a real testnet bitcoin payment channel, with real testnet Bitcoins, see the ``How can I use Teechain`` instructions below. The only difference there is that the transactions presented to the Teechain enclaves will be real testnet transactions placed on the testnet blockchain.

3. If you wish to operate Teechain on the testnet in Intel SGX hardware mode, run ``./prepare_hw_mode.sh`` before executing any of the test scripts.

4. If you wish to operate Teechain tests for the main Bitcoin network, you can execute either of the ``prepare*.sh`` scripts as found in ``test_scripts/mainnet/`` first, before running the tests.

If you prepare the binaries for the testnet, but then accidentally run a mainnet test, the tests will fail. The same is true if you prepare the binaries for the mainnet, but then run a testnet test. This can be a common cause of failures.

## How can I use Teechain?

Teechain is simple to use:

1. First, you execute the Teechain binary to create a Teechain node on your machine.
2. Next, the Teechain node will generate a number of Teechain Bitcoin addresses that you can pay deposits in to. We call these funding deposits.
3. Once you have paid funding deposits into those addresses, you tell your Teechain node about them, such as the amounts paid, the transaction hashes and the transaction ids.
4. You can then begin creating Teechain payment channels with other Teechain nodes, by giving your node the IP address and port of another node.
5. A channel will then be set up between the nodes, and you'll be asked to check that the funding deposits of the other party in the channel are in fact in the Bitcoin blockchain. Note, this is the only manual step required by you. This is to ensure the other party has correctly funded their node.
6. Once both parties have verified the funding deposits of one another in the channel, you can then add funds to the channel, begin making and receiving payments, and if your balance permits, removing funds from the channel. This can occur with high frequency and throughput.
7. Finally, you can settle a payment channel, and your Teechain node will then close the channel and give you a Bitcoin transaction that can be placed on the Bitcoin blockchain reflecting the final balances between the two parties.
8. If you have any funding deposits remaining that haven't been added to payment channels, these can also be returned to you by your Teechain node.

During this process, you can also create other Teechain ``backup nodes`` that can be used to backup the state of your Teechain node to prevent fund loss in the case of failure. We call Teechain nodes that backup the state of another node, a ``backup node``. Teechain nodes that do not backup any state, for example, the Teechain nodes that generate Bitcoin addresses, are called ``primary nodes``.

## Teechain API

To explore and understand the API provided by the Teechain binaries, we outline the command line options below. The test scripts provided in the repository also contain helpful examples of how to use this API to create payment channels. We highly recommend looking at the test scripts if you are still unsure about to how to invoke the binaries.

1. ``./teechan ghost -p PORT_NUMBER`` 

Creates a Teechain enclave (not yet a primary or backup).

This command is the first command that should be invoked. It spawns a teechain ``ghost`` node that listens on the given ``PORT_NUMBER`` for commands. A ghost node is simply a node that has not yet been assigned a ``primary`` or a ``backup`` role.

Note: there are two flags you can pass this command when creating a ghost node (as seen in our example scripts). The ``-b`` flag supresses long output, such as in the case where you want to measure performance but don't want to be hindered by system calls, and the ``-d`` flag forces the ghost node to execute in ``debug mode``, making the transactions produced by the node follow a deterministic pattern for development.

DO NOT give this command the ``-d`` flag unless you are writing tests requiring deterministic transaction generation. This flag will produce invalid transactions that will be rejected by the Bitcoin blockchain.

2. ``./teechan primary -p PORT_NUMBER``       

Assigns an existing ghost Teechain node a primary role.

This command contacts an existing ``ghost`` node on localhost at the given port ``PORT_NUMBER`` and instructs the spawned ghost node to become a primary node. Once a node has been given a primary role, it will maintain this role for life.

3. ``./teechan backup -p PORT_NUMBER``         

Assigns an existing ghost Teechain node a backup role.

This command contacts an existing ``ghost`` node on localhost at the given port ``PORT_NUMBER`` and instructs the spawned ghost node to become a backup node. Once a node has been given a backup role, it will maintain this role for life.

4. ``./teechan setup_deposits NUMBER_OF_DEPOSITS -p PORT_NUMBER`` 

Gives a primary node on localhost at ``PORT_NUMBER`` the number of funding deposits the user wishes to deposit into the node. The Teechain node then returns a set of Teechain bitcoin addresses the user should pay into.

To pay into a Teechain bitcoin address, you need to generate a transaction sending Bitcoin to that address (e.g. using your Bitcoin wallet), and broadcast the transaction on the blockchain.

5. ``./teechan deposits_made RETURN_BTC_ADDRESS   FEE_SATOSHI_PER_BYTE   NUMBER_OF_DEPOSITS   FUNDING_TX_HASH_0   FUNDING_TX_INDEX_0   FUNDING_TX_AMOUNT_0   <REPEATED TX HASH, INDEX AND AMOUNT FOR ALL FUNDING DEPOSITS> -p PORT_NUMBER``

Notifies the Teechain node that funding deposits have been made into the Bitcoin addresses presented by the node through the ``setup_deposits`` command. The arguments then presented to this command, in order, are:

	1. ``RETURN_BTC_ADDRESS`` is the Bitcoin address the Teechain node will pay your funds into when a channel is settled or your deposits are returned.

	2. ``FEE_SATOSHI_PER_BYTE`` is the miner fee you wish to pay when your Teechain node generates a transaction. This is presented to the node in the format of ``satoshi per byte`` of the transaction size.

	3. ``NUMBER_OF_DEPOSITS`` is the number of funding deposits you requested and have paid into. This should match the number given to the ``setup_deposits`` command. 

	4. The remaining arguments are triplets of the form: ``FUNDING_TX_HASH   FUNDING_TX_INDEX   FUNDING_TX_AMOUNT`` which hold the transaction hash, transaction index, and amount (in satoshi) deposited into the Teechain Bitcoin address.

	The order of the triplets on the command line must correspond to the order of the Bitcoin addresses generated through the ``./teechan setup_deposits`` call.

	5. The ``PORT_NUMBER`` of the primary Teechain node on localhost.


6. ``./teechan create_channel -i -r REMOTE_IP_ADDRESS:REMOTE_PORT_NUMBER -p LOCAL_NODE_PORT``

Creates a channel between our Teechain node on localhost at port ``LOCAL_NODE_PORT`` and a remote Teechain node at ``REMOTE_IP_ADDRESS`` and ``REMOTE_PORT_NUMBER``. Note that the ``-i`` flag marks our Teechain node as the initiator of the channel create protocol. 

Before this can be called, the remote Teechain node will need to execute ``./teechan create_channel -p LOCAL_NODE_PORT``, which will allow the remote node to receive an incoming channel create handshake from the initiator.

Once the channel has been established, both Teechain nodes will be notified of the channel ID used to refer to this specific channel, as well as the details of the funding deposits made into the Teechain nodes.

7. ``./teechan verify_deposits CHANNEL_ID -p LOCAL_NODE_PORT``

This should be called on a channel that has already been created (and given an ID of ``CHANNEL_ID``) to notify the Teechain nodes in that channel that one party has manually checked the correctness of the funding deposits made by the counterparty. This process simply involves checking that the funding deposits presented by the remote Teechain node are in fact transactions placed in the blockchain.

Before payments can be sent, both parties will need to call this on their channel.

8. ``./teechan balance CHANNEL_ID -p LOCAL_NODE_PORT``

This prints the current balances of the parties in a specific channel (denoted by CHANNEL_ID). If no deposits are added to a channel, the balances will be 0.

9. ``./teechan add_deposit CHANNEL_ID DEPOSIT_ID -p LOCAL_NODE_PORT``

This adds a deposit to the channel referred to by ``CHANNEL_ID``. The ``DEPOSIT_ID`` is the index of the funding deposits presented to the node through the ``./teechan deposits_made`` call. Funding deposits are indexed starting at 0.

A deposit can only be added to 1 channel at a time.

10. ``./teechan remove_deposit CHANNEL_ID DEPOSIT_ID -p LOCAL_NODE_PORT``

This removes a deposit from the channel referred to by ``CHANNEL_ID``. The ``DEPOSIT_ID`` is the index of the funding deposits presented to the node through the ``./teechan deposits_made`` call. Funding deposits are indexed starting at 0.

11. ``./teechan send CHANNEL_ID AMOUNT -p LOCAL_NODE_PORT``

This sends the specified ``AMOUNT`` of satoshi along the given ``CHANNEL_ID`` to the remote party and updates the balances of the channel.

12. ``./teechan settle_channel CHANNEL_ID -p LOCAL_NODE_PORT``

This terminates the channel specified by ``CHANNEL_ID``, closes the channel, and generates a Bitcoin transaction representing the final state of the channel. This transaction can then be broadcast to the Bitcoin network and placed on the blockchain. Broadcasting the transaction to the network could be performed through various online websites, such as [here](https://live.blockcypher.com/btc/pushtx/), or using a locally running Bitcoin node.

13. ``./teechan return_unused_deposits -p LOCAL_NODE_PORT``

This returns the deposits currently not placed in any channels by generating a Bitcoin transaction returning the funds of the deposits back to the owner's return address. This will also mark the deposits as spent inside the Teechain node, so they can no longer be placed into channels.

13. ``./teechan shutdown -p LOCAL_NODE_PORT``

This shutdowns your Teechain node by first: (i) returning any unused deposits held by the node; and then (ii) terminating all currently open channels. 

Warning: this command will kill your Teechain node. No more payments, or channels can be opened using this node.

14. ``./teechan add_backup -i -r REMOTE_IP_ADDRESS:REMOTE_PORT_NUMBER -p LOCAL_NODE_PORT``

Assigns a ``backup node`` to become a backup for a ``primary node``. This command is similar to the ``./teechan create_channel`` command in that it creates a secure backup channel between our Teechain primary node and a Teechain backup node. 

Before this can be called, the primary node will need to execute ``./teechan add_backup -p LOCAL_NODE_PORT``, which will allow it to receive an incoming backup channel create handshake from the backup node.

Once the backup channel has been established, the backup node will replicate all state of the primary node securely. In the case one of the node fails, the ``./teechan settle_channel``, ``./teechan return_unused_deposits`` and ``./teechan shutdown`` commands can then be invoked on the remaining alive node to retrieve all funds held in channels or by the Teechain primary.

Multiple backup's can be added to a single primary node, forming a backup chain. See the example test scripts for how to construct these backup channels.

## FAQs

#### What is a payment channel?
If you're confused about payment channels, payment networks, and the problem Teechain is trying to solve, we recommend reading
our papers. These are, [Teechan](https://arxiv.org/abs/1612.07766) and [Teechain](https://arxiv.org/abs/1707.05454).

#### What is Intel SGX?

Intel SGX (Software Guard Extensions) is a set of extensions provided to the Intel architecture in recent commodity Intel processors that enable application code to be executed with confidentiality and integrity guarantees. SGX provides trusted execution environments known as secure "enclaves" that isolate code and data using hardware mechanisms in the CPU. Integrity and confidentiality guarantees are provided even if all priviledged software, such as the operating system or hypervisor, are compromised. Read more about Intel SGX [here](https://software.intel.com/en-us/sgx).

Teechain leverages Intel SGX to secure its payment channels.

#### What about side channel attacks?

Side-channel attacks can violate the confidentiality of data held inside a TEE (trusted execution environment), such as an Intel SGX enclave. Teechain protects against timing and memory-access based side-channel attacks through a correct by construction design. All sensitive data held in the TEE is secure against these types of attacks. All other data held in the TEE not deemed sensitive may leak through a side-channel. However, if non-sensitive data is leaked in Teechain, this does not grant an attacker the ability to steal funds, or to control payment channels.

To protect sensitive-data in the TEE, Teechain employs the use of side-channel resistant operations. These are specifically 
constructed code blocks, such as functions or methods, that are implemented to be free from software-based side-channel attacks. By trusting the security of these code blocks and ensuring that sensitive data in the TEE is only ever created, accessed or destroyed through a direct invocation of these code blocks, Teechain can protect sensitive-data from side-channel attacks throughout the lifetime of that data. In addition, by employing the use of side-channel resistant encryption and decryption operations, sensitive-data can be protected and exchanged between TEEs without compromising the confidentiality and integrity of that data.

#### Have you run this on the Bitcoin mainnet?

We have operated Teechain payment channels on the Bitcoin mainnet. For example, the following sets of transactions show a simple payment channel created by Teechain for the mainnet. The channel contained two funding deposits of 500K satoshi each, from each party in the channel. We then performed around 50 million sends at random, back and forth between the two parties, before settling the channel and pushing the generated settlement transaction on the blockchain.

The details of the payment channel are as follows:

Alice's funding deposit paid 500k satoshi into Teechain address ``1PmF4XsLctLWfAQnnB8VC81Yh6xdYZpDAz``, using transaction ``75c619abbed28063683c87747958ba69744f8a17a0dfcf38665c2a6ab8db930d``, index ``1``. [Here](https://blockchain.info/tx/75c619abbed28063683c87747958ba69744f8a17a0dfcf38665c2a6ab8db930d) is the transaction on the Bitcoin Blockchain.

Bob's funding deposit paid 500k satoshi into Teechain address ``1PmF4XsLctLWfAQnnB8VC81Yh6xdYZpDAz ``, using transaction ``75c619abbed28063683c87747958ba69744f8a17a0dfcf38665c2a6ab8db930d``, index ``1``. [Here](https://blockchain.info/tx/75c619abbed28063683c87747958ba69744f8a17a0dfcf38665c2a6ab8db930d) is the transaction on the Bitcoin Blockchain.

We then performed over 50 million sends between the two parties, before settling the channel on Alice's side. The settlement transaction (seen [here](https://blockchain.info/tx/5ee6fa414511f55299b031d0db7e594b5c0ea98daae2283afdc3f521b86b89a4)) paid around 300k satoshi back to Bob, and 700k satoshi back to Alice (minus the miner fee, paid by Alice, calculated at 100 satosih per byte approximately).

#### I'm having technical problems, what should I do?

Depending on the type of errors you're seeing, some simple checks/fixes are as follows:

1. Run the ``kill.sh`` script to kill any previously running instances of Teechain (careful this will kill ALL Teechain instances on your machine!) 

2. Sudo access might be required to mount a ram disk in the Teechain tests. A ram disk is only used for performance reasons, and Teechain can still run without it.

3. Ensure you have correct versions of the Intel SGX, PSW and Driver installed (only the SDK is required for simulation mode). Make sure you can run the example Intel SGX applications too, as the problem might not be with our binaries.

4. If the Teechain processes die unexpectedly, check the log files for more information (an error message is usually provided).

If you're still having problems using Teechain, feel free to open an issue on our Github [here](https://github.com/lsds/Teechain/issues).

## Questions/Comments/Feedback

If you have any questions or comments, or would like to provide feedback, feel free to raise an issue on the [GitHub](https://github.com/lsds/Teechain), or email us directly (our contact information can be found [here](https://teechain.network#contact));

## License

Copyright (C) 2016-2018, Imperial College London & Cornell University

All rights reserved.

Primary Author: Joshua Lind.

Redistribution in source or binary forms, with or without modification, are expressly prohibited.

This release is issued to specially designated people for the sole purpose of providing
feedback back to the developers.

It is illegal to remove this notice, to incorporate this code into any other software, to make
it available to third parties not expressly authorized by the authors.  Not for use in
production, or for use in money transmission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS  * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED  * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
