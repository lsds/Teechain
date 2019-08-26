# Teechain: A Secure Payment Network with Asynchronous Blockchain Access

Teechain is a layer two off-chain payment network for blockchains. It utilizes trusted execution environments (TEEs) to perform secure, efficient and scalable fund transfers, while only requiring asynchronous access to the underlying blockchain.

To find out more about Teechain, or read our academic papers, please visit us at: [teechain.network](https://teechain.network).


## Teechain Alpha Release

This repository contains an alpha release of the Teechain source code for the Bitcoin network. This release is a strict subset of all the features described in the Teechain paper. It includes the following artifacts and functionality:

1. Teechain payment channels including static deposit creation, association and removal.

2. Support for force-freeze chain replication (i.e., creating committee chains statically and replicating state down the chain)

3. Payment channel settlement for 1-out-of-m committee chain deposits (i.e, deposits where any 1 member in the committee chain can sign and spend the deposit)

4. Some simple benchmarking and demo scripts showing how to create, operate and settle payment channels.


## Disclaimer:

This release supports both the Bitcoin testnet and the Bitcoin mainnet. Given the early nature of this release, we do not recommend placing real money in Teechain operated channels. This software is to be taken as a demonstration of Teechain's capabilities.

The Teechain Network and its affiliates are not responsible for the loss of any funds, or any damages that might be incurred by using our software. Any and all uses of the software provided here are at the risk of the user. We accept no liability.


## What do I need to use Teechain?

Teechain uses trusted execution environments (TEEs), and this release targets Intel SGX as the TEE. However, if you do not have access to an Intel SGX-enabled machine, you can still operate Teechain in simulation mode.

To run Teechain in simulation mode, you will need to install the Intel SGX SDK. Follow the instructions below.

To run Teechain in hardware production mode, you'll need to install the Intel SGX SDK, PSW, and the SGX Driver, as well as have access to an SGX-enabled machine. Follow the instructions below.

If you'd like to see whether or not you have an Intel SGX enabled processor, follow the instructions [here](https://github.com/ayeks/SGX-hardware).


## Teechain requirements/prerequisites

To install and run Teechain, we recommend using Ubuntu 16.04 LTS. Teechain may also work on other versions of Linux, however, we have not tested these at present. There is currently no support for Windows.

1. First, you will need to install the Intel SGX SDK for Linux, which can be found [here](https://github.com/intel/linux-sgx). We recommend installing [version 2.1](https://github.com/intel/linux-sgx/releases/tag/sgx_2.1). 

Note, when installing the SDK and being asked where to install the files, we recommend specifying ``/opt/intel/``, as this is where our scripts look for the environment variables.

2. To run hardware production enclaves, you will need an Intel SGX enabled machine and to install the SGX PSW (instructions can be found on the Linux SGX SDK GitHub [here](https://github.com/intel/linux-sgx)). You will also need to install the Intel SGX Driver [here](https://github.com/intel/linux-sgx-driver).
For both the PSW and the Driver we recommend installing version 2.1 ([here](https://github.com/intel/linux-sgx/releases/tag/sgx_2.1) and [here](https://github.com/intel/linux-sgx-driver/releases/tag/sgx_driver_2.1)), and installing to the path ``/opt/intel/``.

3. Ensure that you can run some of the Intel SGX provided sample applications first, before trying to run Teechain in simulation or hardware mode. Assuming the SDK was installed to ``/opt/intel/``, the example applications should be in ``/opt/intel/sgxsdk/SampleCode/``

4. Teechain requires the following development libraries, so also install these by running: ``sudo apt-get install libcurl4-openssl-dev libssl-dev``.

5. Finally, you'll need to configure the libsecp256k1 library. Go into the ``src/trusted/libs/bitcoin/secp256k1`` directory and execute: ``chmod +x autogen.sh && ./autogen.sh && ./configure``.

## Checking Teechain works/Running Teechain examples

This release includes test scripts that execute various features of Teechain payment channels. To check that Teechain is working, and has all the required components, we can execute some tests:

1. First, to build Teechain, decide which mode you would like to build it for, simulation, hardware debug, or hardware production mode. We recommend trying simulation mode first. Go into the ``src/bin`` directory, run ``./gen_key.sh`` to generate a private key for enclave signing and then execute the relevant build script, e.g. ``./make_sim.sh`` for simulation mode.

2. Next, execute any one of the test scripts in the ``src/bin/testnet`` directory, such as ``./teechain_send.sh``, to check that things are working. ``./teechain_send.sh`` will setup a simple channel between two endpoints on the local machine, add deposits to those channels, send some payments, check balances of the channel, terminate the channel, and return any unused deposits held by the enclave. The output should indicate a successful run (i.e., the last line should say something like "test passed!") Ignore any messages saying "process killed": the scripts simply kill the teechain processes at the end of each test using the ``./kill.sh`` script. 

Assuming everything executes correctly, you will have succesfully operated a Teechain payment channel in simulation mode for the testnet. Note: no real testnet bitcoins would have been exchanged in this test script because the transactions presented to the enclaves are not legitimate transactions that have been placed in the testnet blockchain. To actually operate a real testnet bitcoin payment channel, with real testnet Bitcoins, see the ``How can I use Teechain`` instructions below. The only difference there is that the transactions presented to the Teechain enclaves will be real testnet transactions placed on the testnet blockchain.

3. If you wish to operate Teechain on the testnet in Intel SGX hardware mode, run ``./make.sh`` for hardware pre-release mode. To run Teechain in production, execute ``make_real.sh`` for hardware production mode. Note that this will require a whitelisted signing key authorised by Intel. To see the difference between different compilation modes, look [here](https://software.intel.com/en-us/blogs/2016/01/07/intel-sgx-debug-production-prelease-whats-the-difference).


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

During this process, you can also create other Teechain ``backup nodes`` that can be used to backup the state of deposits into committee chains. Commitee chains are responsible for securing deposits and for fault tolerance. We call Teechain nodes that backup the state of another node, a ``backup node``. For simplicity, this release only supports backing up 1-out-of-m deposits, i.e. any node in the committee chain can spend the deposit to produce a settlement. See "Why are some features not supported" below for more details.


## Operating on the Bitcoin mainnet

If you wish to operate Teechain on the main Bitcoin network, you'll need to build Teechain for the mainnet. To do so, open the file ``src/trusted/teechain.cpp`` and change the ``testnet`` variable to ``false``, then remake Teechain using the build scripts. 

Note: if you build Teechain for the testnet, but then run a mainnet test, the tests will fail with an illegal instruction exception. The same is true if you build for the mainnet, but then run a testnet test. This can be a common cause of failures.


## Why are some features not supported?

There are several features described in the Teechain paper not included in this release. These include: multi-hop payments, support for m-out-of-n deposits, dynamic deposit creation, dynamic committees, committee signature collection and the benchmarking of large Teechain network topologies.

For various reasons, these features will only be open-sourced in the future.


## Benchmarking a payment channel

To benchmark a payment channel, the script ``teechain_benchmark.sh`` in the ``src/bin/testnet`` or ``src/bin/mainnet`` directories shows how to set up a payment channel and benchmark it. Execute this script to see how it works.


## What happens for Intel remote attestation?

This release includes support for remote attestation through the Intel Attestation Service (IAS). Remote attestation generates a signed enclave measurement, sends it to the IAS for signature verification, and then compares the measurement to the expected and trusted "Teechain measurement". By default, remote attestation is disabled and attestation is ignored. To enable remote attestation, do the following:

1. Modify ``src/sgx_t.mk`` and ``src/sgx_u.mk`` to add the ``DSGX_ATTEST`` flag back to the ``SGX_COMMON_CFLAGS`` (i.e. just search for ``DSGX_ATTEST`` and uncomment the defines from these two files)

2. Modify all relevent certificate, public and private key strings in both the ``src/trusted/libs/remote_attestation`` and ``src/untrusted/libs/remote_attestation`` directories.

Given the fact that this only a partial release of Teechain, we expect that those who wish to enable remote attestation might run into some issues regarding where to put IAS keys, the signed "Teechain measurement" etc. As such, if anyone wants to enable remote attestation for Teechain, feel free to reach out to the authors for further support.

## Teechain API

To explore and understand the API provided by the Teechain binaries, we outline the command line options below. The test scripts provided in the repository also contain helpful examples of how to use this API to create payment channels. We highly recommend looking at the test scripts if you are still unsure about to how to invoke the binaries.

1. ``./teechain ghost -p PORT_NUMBER`` 

Creates a Teechain enclave (not yet a primary or backup).

This command is the first command that should be invoked. It spawns a teechain ``ghost`` node that listens on the given ``PORT_NUMBER`` for commands. A ghost node is simply a node that has not yet been assigned a ``primary`` or a ``backup`` role.

2. ``./teechain primary -p PORT_NUMBER``       

Assigns an existing ghost Teechain node a primary role. Add the ``-m`` flag to enable monotonic counter emulation for stable storage.

This command contacts an existing ``ghost`` node on localhost at the given port ``PORT_NUMBER`` and instructs the spawned ghost node to become a primary node. Once a node has been given a primary role, it will maintain this role for life.

3. ``./teechain backup -p PORT_NUMBER``         

Assigns an existing ghost Teechain node a backup role.

This command contacts an existing ``ghost`` node on localhost at the given port ``PORT_NUMBER`` and instructs the spawned ghost node to become a backup node. Once a node has been given a backup role, it will maintain this role for life.

4. ``./teechain setup_deposits NUMBER_OF_DEPOSITS -p PORT_NUMBER`` 

Gives a primary node on localhost at ``PORT_NUMBER`` the number of funding deposits the user wishes to deposit into the node. The Teechain node then returns a set of Teechain bitcoin addresses the user should pay into.

To pay into a Teechain bitcoin address, you need to generate a transaction sending Bitcoin to that address (e.g. using your Bitcoin wallet), and broadcast the transaction on the blockchain.

5. ``./teechain deposits_made RETURN_BTC_ADDRESS   FEE_SATOSHI_PER_BYTE   NUMBER_OF_DEPOSITS   FUNDING_TX_HASH_0   FUNDING_TX_INDEX_0   FUNDING_TX_AMOUNT_0   <REPEATED TX HASH, INDEX AND AMOUNT FOR ALL FUNDING DEPOSITS> -p PORT_NUMBER``

Notifies the Teechain node that funding deposits have been made into the Bitcoin addresses presented by the node through the ``setup_deposits`` command. The arguments then presented to this command, in order, are:

	1. ``RETURN_BTC_ADDRESS`` is the Bitcoin address the Teechain node will pay your funds into when a channel is settled or your deposits are returned.

	2. ``FEE_SATOSHI_PER_BYTE`` is the miner fee you wish to pay when your Teechain node generates a transaction. This is presented to the node in the format of ``satoshi per byte`` of the transaction size.

	3. ``NUMBER_OF_DEPOSITS`` is the number of funding deposits you requested and have paid into. This should match the number given to the ``setup_deposits`` command. 

	4. The remaining arguments are triplets of the form: ``FUNDING_TX_HASH   FUNDING_TX_INDEX   FUNDING_TX_AMOUNT`` which hold the transaction hash, transaction index, and amount (in satoshi) deposited into the Teechain Bitcoin address.

	The order of the triplets on the command line must correspond to the order of the Bitcoin addresses generated through the ``./teechain setup_deposits`` call.

	5. The ``PORT_NUMBER`` of the primary Teechain node on localhost.


6. ``./teechain create_channel -i -r REMOTE_IP_ADDRESS:REMOTE_PORT_NUMBER -p LOCAL_NODE_PORT``

Creates a channel between our Teechain node on localhost at port ``LOCAL_NODE_PORT`` and a remote Teechain node at ``REMOTE_IP_ADDRESS`` and ``REMOTE_PORT_NUMBER``. Note that the ``-i`` flag marks our Teechain node as the initiator of the channel create protocol. 

Before this can be called, the remote Teechain node will need to execute ``./teechain create_channel -p LOCAL_NODE_PORT``, which will allow the remote node to receive an incoming channel create handshake from the initiator.

Once the channel has been established, both Teechain nodes will be notified of the channel ID used to refer to this specific channel, as well as the details of the funding deposits made into the Teechain nodes.

7. ``./teechain verify_deposits CHANNEL_ID -p LOCAL_NODE_PORT``

This should be called on a channel that has already been created (and given an ID of ``CHANNEL_ID``) to notify the Teechain nodes in that channel that one party has manually checked the correctness of the funding deposits made by the counterparty. This process simply involves checking that the funding deposits presented by the remote Teechain node are in fact transactions placed in the blockchain.

Before payments can be sent, both parties will need to call this on their channel.

8. ``./teechain balance CHANNEL_ID -p LOCAL_NODE_PORT``

This prints the current balances of the parties in a specific channel (denoted by CHANNEL_ID). If no deposits are added to a channel, the balances will be 0.

9. ``./teechain add_deposit CHANNEL_ID DEPOSIT_ID -p LOCAL_NODE_PORT``

This adds a deposit to the channel referred to by ``CHANNEL_ID``. The ``DEPOSIT_ID`` is the index of the funding deposits presented to the node through the ``./teechain deposits_made`` call. Funding deposits are indexed starting at 0.

A deposit can only be added to 1 channel at a time.

10. ``./teechain remove_deposit CHANNEL_ID DEPOSIT_ID -p LOCAL_NODE_PORT``

This removes a deposit from the channel referred to by ``CHANNEL_ID``. The ``DEPOSIT_ID`` is the index of the funding deposits presented to the node through the ``./teechain deposits_made`` call. Funding deposits are indexed starting at 0.

11. ``./teechain send CHANNEL_ID AMOUNT -p LOCAL_NODE_PORT``

This sends the specified ``AMOUNT`` of satoshi along the given ``CHANNEL_ID`` to the remote party and updates the balances of the channel.

12. ``./teechain settle_channel CHANNEL_ID -p LOCAL_NODE_PORT``

This terminates the channel specified by ``CHANNEL_ID``, closes the channel, and generates a Bitcoin transaction representing the final state of the channel. This transaction can then be broadcast to the Bitcoin network and placed on the blockchain. Broadcasting the transaction to the network could be performed through various online websites, such as [here](https://live.blockcypher.com/btc/pushtx/), or using a locally running Bitcoin node.

13. ``./teechain return_unused_deposits -p LOCAL_NODE_PORT``

This returns the deposits currently not placed in any channels by generating a Bitcoin transaction returning the funds of the deposits back to the owner's return address. This will also mark the deposits as spent inside the Teechain node, so they can no longer be placed into channels.

13. ``./teechain shutdown -p LOCAL_NODE_PORT``

This shutdowns your Teechain node by first: (i) returning any unused deposits held by the node; and then (ii) terminating all currently open channels. 

Warning: this command will kill your Teechain node. No more payments, or channels can be opened using this node.

14. ``./teechain add_backup -i -r REMOTE_IP_ADDRESS:REMOTE_PORT_NUMBER -p LOCAL_NODE_PORT``

Assigns a ``backup node`` to become a backup for a ``primary node``. This command is similar to the ``./teechain create_channel`` command in that it creates a secure backup channel between our Teechain primary node and a Teechain backup node. 

Before this can be called, the primary node will need to execute ``./teechain add_backup -p LOCAL_NODE_PORT``, which will allow it to receive an incoming backup channel create handshake from the backup node.

Once the backup channel has been established, the backup node will replicate all state of the primary node securely. In the case one of the node fails, the ``./teechain settle_channel``, ``./teechain return_unused_deposits`` and ``./teechain shutdown`` commands can then be invoked on the remaining alive node to retrieve all funds held in channels or by the Teechain primary.

Multiple backup's can be added to a single primary node, forming a backup chain. See the example test scripts for how to construct these backup channels.

## Deterministc output for test scripts (-d)

Note: there are two flags you can pass to the ``./teechain ghost`` command when creating a ghost node (as seen in our example scripts). The ``-b`` flag supresses long output, such as in the case where you want to measure performance but don't want to be hindered by system calls, and the ``-d`` flag forces the ghost node to execute in ``debug mode``, making the transactions produced by the node follow a deterministic pattern for development.

DO NOT give this command the ``-d`` flag unless you are writing tests requiring deterministic transaction generation. This flag will produce invalid transactions that will be rejected by the Bitcoin blockchain!

## High-level source code overview

The source code of Teechain is split into two parts: the trusted code, and the untrusted code. Naturally, the trusted
code executes inside the enclave, and the untrusted code executes outside. These are seperated by the ``trusted`` and ``untrusted`` directories. The interface between the trusted and untrusted components is defined in ``src/trusted/teechain.edl``. This interface follows the semantics provided by the Intel SGX SDK: ecalls call into the enclave, and ocalls call out of enclave.

Whenever an API call is executed, a new command line process is spawned (see ``src/untrusted/command_line_interface.cpp``) that sends a message to the Teechain instance (all communication happens over sockets). The teechain instance reads the command from the socket, decodes it, and executes it appropriately (see ``src/untrusted/teechain.cpp``). Depending on the command requested, the Teechain instance may make an ecall into the enclave, execute whatever command was requested, return from the enclave, and send a message to the command line process regarding whether or not the command was successfully executed.

The ``src/trusted/teechain.cpp`` file contains the majority of the enclave entry points and logic (i.e., typically when an ecall is made, it will be made into some function in this file). A subset of the Bitcoin core code has been ported to execute inside the enclave, see: ``src/trusted/libs/bitcoin``, however we have only ported several methods such as transaction signing, decoding (we only ported what we required). If you have specific questions about how we did this, please reach out.



## FAQs

#### What is a payment channel?
If you're confused about payment channels, payment networks, and the problem Teechain is trying to solve, we recommend reading our papers at: [teechain.network](https://teechain.network).

#### What is Intel SGX?

Intel SGX (Software Guard Extensions) is a set of extensions provided to the Intel architecture in recent commodity Intel processors that enable application code to be executed with confidentiality and integrity guarantees. SGX provides trusted execution environments known as secure "enclaves" that isolate code and data using hardware mechanisms in the CPU. Integrity and confidentiality guarantees are provided even if all priviledged software, such as the operating system or hypervisor, are compromised. Read more about Intel SGX [here](https://software.intel.com/en-us/sgx).

Teechain leverages Intel SGX to secure its payment channels.

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

5. Segmentation faults on startup: this could be because your machine doesn't have enough memory to run Teechain. Each instance requires about 4GB of RAM by default (see ``src/trusted/teechain.config.xml`` to change this)! Note, if you give it too little RAM, it might have problems at runtime.

If you're still having problems using Teechain, feel free to open an issue on our Github [here](https://github.com/lsds/Teechain/issues).

## Questions/Comments/Feedback

If you have any questions or comments, or would like to provide feedback, feel free to raise an issue, or email us directly (our contact information can be found [here](https://teechain.network#contact));

## License

/*
 *
 * Copyright ©  <2016 to 2019>  by Imperial College London, Cornell University and the Cornell Research Foundation, Inc.  All Rights Reserved.
 *
 * Author: Joshua Lind.
 *
 * Permission to use, copy, modify and distribute any part of Teechain (“WORK”) and its associated copyrights for educational, research and non-profit purposes, without fee, and without a written agreement is hereby granted, provided that the above copyright notice, this paragraph and the following three paragraphs appear in all copies.
 *
 * Those desiring to incorporate WORK into commercial products or use WORK and its associated copyrights for commercial purposes should contact the Center for Technology Licensing at Cornell University at 395 Pine Tree Road, Suite 310, Ithaca, NY 14850; email: ctl-connect@cornell.edu; Tel: 607-254-4698; FAX: 607-254-5454 for a commercial license.
 *
 * IN NO EVENT SHALL IMPERIAL COLLEGE LONDON, THE CORNELL RESEARCH FOUNDATION, INC. AND CORNELL UNIVERSITY BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF WORK AND ITS ASSOCIATED COPYRIGHTS, EVEN IF IMPERIAL COLLEGE LONDON, THE CORNELL RESEARCH FOUNDATION, INC. AND CORNELL UNIVERSITY MAY HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE WORK PROVIDED HEREIN IS ON AN "AS IS" BASIS, AND IMPERIAL COLLEGE LONDON, THE CORNELL RESEARCH FOUNDATION, INC. AND CORNELL UNIVERSITY HAVE NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS. IMPERIAL COLLEGE LONDON, THE CORNELL RESEARCH FOUNDATION, INC. AND CORNELL UNIVERSITY MAKE NO REPRESENTATIONS AND EXTEND NO WARRANTIES OF ANY KIND, EITHER IMPLIED OR EXPRESS, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, OR THAT THE USE OF WORK AND ITS ASSOCIATED COPYRIGHTS WILL NOT INFRINGE ANY PATENT, TRADEMARK OR OTHER RIGHTS.
 *
 */
