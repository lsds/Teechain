#!/bin/bash          
set -e

if test -d bin; then cd bin; fi

bold=`tput bold`
reset=`tput sgr0`

pushd ../

echo "${bold}Making teechain for real hardware and in production mode!${reset}"
make clean
make SGX_MODE=HW

popd
