#!/bin/bash          
set -e

if test -d bin; then cd bin; fi

bold=`tput bold`
reset=`tput sgr0`

pushd ../

echo "${bold}Making teechain for real hardware!${reset}"
make clean
make SGX_MODE=HW SGX_DEBUG=1

popd
