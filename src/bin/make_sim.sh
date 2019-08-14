#!/bin/bash          
set -e

if test -d bin; then cd bin; fi

bold=`tput bold`
reset=`tput sgr0`

pushd ../

echo "${bold}Making teechain for simulation mode!${reset}"
make clean
make SGX_MODE=SIM SGX_DEBUG=1 

popd
