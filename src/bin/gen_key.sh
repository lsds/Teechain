#!/bin/bash          
set -e

if test -d bin; then cd bin; fi

bold=`tput bold`
reset=`tput sgr0`

pushd ../

echo "${bold}Generating a private key for enclave signing!${reset}"
openssl genrsa -out teechain_private.pem -3 3072
popd
