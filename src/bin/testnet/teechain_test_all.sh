#!/bin/bash
set -e

# Colour constants
bold=`tput bold`
green=`tput setaf 2`
red=`tput setaf 1`
reset=`tput sgr0`

echo "${bold}Running all the tests! This might take a while...!${reset}"

./teechain_send.sh

sleep 1

./teechain_deposits.sh

sleep 1

./teechain_single_hop.sh

sleep 1

./teechain_settle.sh

sleep 1

./teechain_benchmark.sh

sleep 1

./teechain_backups_simple.sh

sleep 1

./teechain_backups_break.sh

sleep 1

./teechain_backups_settle.sh

sleep 1

./teechain_backups_send.sh

sleep 1

./teechain_backups_deposits.sh

sleep 1

./teechain_backups_benchmark.sh

echo "...${bold}Looks like all the tests passed!!${reset}"
