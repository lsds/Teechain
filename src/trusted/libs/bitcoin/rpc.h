#include <string>
#include <univalue.h>
#include <key.h>
#include <base58.h>
#include "utilstrencodings.h"

/* RPC like interface to trusted bitcoin library */
void initializeECCState();
UniValue executeCommand(std::string args);
