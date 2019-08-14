#include "state.h"

// Global state of this enclave
TeechanState teechain_state = Ghost;

bool check_state(TeechanState state) {
    if (teechain_state != state) {
        return false;
    }
    return true;
}

