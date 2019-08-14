#include "sgx_tkey_exchange.h"

#include "channel.h"

#ifndef SGX_ATTEST
// Dummy encryption key for teechain channels without attestation
sgx_aes_gcm_128bit_key_t simulation_network_key = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
#endif

// encrypt using the service provider symmetric key (i.e. the key generated when we checked
// the validity of the other enclave's quote against IAS)
int sgx_encrypt(ChannelState *state, unsigned char *plain, int plainlen, unsigned char *cypher, sgx_aes_gcm_128bit_tag_t *p_out_mac) {
    //TODO: change all iv's to maintain state and not start at 0 on every message
    uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};

    return sgx_rijndael128GCM_encrypt(
#ifdef SGX_ATTEST
            &(state->g_sp_db).sk_key,
#else
            &simulation_network_key,
#endif
            (const uint8_t*) plain,
            plainlen,
            (uint8_t*) cypher,
            &aes_gcm_iv[0],
            SAMPLE_SP_IV_SIZE,
            NULL,
            0,
            p_out_mac);
}

// decrypt using the enclave symmetric key (i.e. the key generated when we provided our quote to be
// checked by the other enclave)
int sgx_decrypt(unsigned char *cypher, int cypherlen, unsigned char *p_gcm_mac, sgx_ra_context_t context, unsigned char *plain) {
    //TODO: change all iv's to maintain state and not start at 0 on every message
    uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};

    sgx_ec_key_128bit_t sk_key;
    sgx_status_t ret = SGX_SUCCESS;

#ifdef SGX_ATTEST
    ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    if (SGX_SUCCESS != ret) {
        printf("sgx_ra_get_keys failed");
        return ret;
    }
#endif

    return sgx_rijndael128GCM_decrypt(
#ifdef SGX_ATTEST
             &sk_key,
#else
             &simulation_network_key,
#endif
             (const uint8_t*) cypher,
             cypherlen,
             (uint8_t*) plain,
             &aes_gcm_iv[0],
             SAMPLE_SP_IV_SIZE,
             NULL,
             0,
             (const sgx_aes_gcm_128bit_tag_t *) (p_gcm_mac));
}
