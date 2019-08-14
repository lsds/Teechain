/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "service_provider.h"
#include "ecp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string>
#include "ias_ra.h"
#include "teechain_t.h"
#include "utils.h"

#include <univalue.h>
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"

uint8_t SPID[16] = { 
        0x8F, 0xAA, 0x36, 0x2A,
        0x45, 0x12, 0x94, 0x1C,
        0x2E, 0xA7, 0x44, 0x3F,
        0x4E, 0xDB, 0x33, 0x94,
};

#define UNUSED(expr) do { (void)(expr); } while (0)

#if !defined(SWAP_ENDIAN_DW)
    #define SWAP_ENDIAN_DW(dw)	((((dw) & 0x000000ff) << 24)                \
    | (((dw) & 0x0000ff00) << 8)                                            \
    | (((dw) & 0x00ff0000) >> 8)                                            \
    | (((dw) & 0xff000000) >> 24))
#endif
#if !defined(SWAP_ENDIAN_32B)
    #define SWAP_ENDIAN_32B(ptr)                                            \
{\
    unsigned int temp = 0;                                                  \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[0]);                       \
    ((unsigned int*)(ptr))[0] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[7]);  \
    ((unsigned int*)(ptr))[7] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[1]);                       \
    ((unsigned int*)(ptr))[1] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[6]);  \
    ((unsigned int*)(ptr))[6] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[2]);                       \
    ((unsigned int*)(ptr))[2] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[5]);  \
    ((unsigned int*)(ptr))[5] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[3]);                       \
    ((unsigned int*)(ptr))[3] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[4]);  \
    ((unsigned int*)(ptr))[4] = temp;                                       \
}
#endif

#define MAX_ENCODING_LENGTH 4096

// This is the ECDSA NIST P-256 private key used to sign platform_info_blob.
// This private
// key and the public key in SDK untrusted KElibrary should be a temporary key
// pair. For production parts an attestation server will sign the platform_info_blob with the
// production private key and the SDK untrusted KE library will have the public
// key for verifcation.

static const sgx_ec256_private_t g_rk_priv_key =
{{
    0x63,0x2c,0xd4,0x02,0x7a,0xdc,0x56,0xa5,
    0x59,0x6c,0x44,0x3e,0x43,0xca,0x4e,0x0b,
    0x58,0xcd,0x78,0xcb,0x3c,0x7e,0xd5,0xb9,
    0xf2,0x91,0x5b,0x39,0x0d,0xb3,0xb5,0xfb
}};

static std::string intel_ias_public_key_pem = "TODO: PROVIDE A VALID BASE64 ENCODED PUBLIC KEY TO CHECK INTEL IAS SERVER";

static std::string teechain_mrenclave_public_key_pem = "TODO: PROVIDE A VALID BASE64 ENCODED PUBLIC KEY BY WHICH TO VERIFY THE EXPECTED ENCLAVE HASH";

static std::string encode_string(std::string input) {
    unsigned char encoded_output[MAX_ENCODING_LENGTH];
    size_t encoded_output_length;
    if (mbedtls_base64_encode(encoded_output, MAX_ENCODING_LENGTH, &encoded_output_length, (const unsigned char*) input.c_str(), input.length()) != 0) {
        printf("Error: mbedtls_base64_encode!");
        return false;
    }

    std::string encoded_output_string = std::string((const char*) encoded_output, encoded_output_length);
    return encoded_output_string;
}

static std::string decode_string(std::string input) {
    unsigned char decoded_output[MAX_ENCODING_LENGTH];
    size_t decoded_output_length;
    if (mbedtls_base64_decode(decoded_output, MAX_ENCODING_LENGTH, &decoded_output_length, (const unsigned char*) input.c_str(), input.length()) != 0) {
        printf("Error: mbedtls_base64_decode!");
        return false;
    }

    std::string decoded_output_string = std::string((const char*) decoded_output, decoded_output_length);
    return decoded_output_string;
}

// verifies the given quote and signature using the given public key
bool verify_signature(const std::string& msg, const std::string& signature, const std::string& public_key) {
    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Read RSA Public Key
    if ((ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*) public_key.c_str(), public_key.length() + 1)) != 0 ) {
        printf( " failed\n  ! mbedtls_pk_parse_public_key returned -0x%04x\n", -ret );
        return false;
    }

    // Get RSA Context from PK Key
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
    unsigned char hash[33];
    hash[32] = '\0';

    // Compute the SHA-256 hash of the given message
    if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char*) msg.c_str(), msg.length(), hash)) != 0 ) {
        printf( " failed\n  ! Could not read %s\n\n", msg.c_str());
        return false;
    }

    // Compare the hash of the given message to the hash signed by the IAS
    if ((ret = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, hash, (const unsigned char*) signature.c_str())) != 0) {
        printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned -0x%0x\n\n", -ret );
        return false;
    }

    mbedtls_rsa_free(rsa);
    return true;
}

static bool verify_response_quote(std::string nonce, std::string response_body) {
    // Parse Response to JSON
    UniValue response;
    if (!response.read(response_body)) {
        printf("Failed to parse response to JSON!");
        return false;
    }

    // Check freshness of nonce
    if (remove_surrounding_quotes(response["nonce"].write()) != nonce) {
        printf("Returned nonce is invalid!");
        return false;
    }

    // Check enclave quote status:
    // TODO(joshlind): remove the workaround required to support GROUP_OUT_OF_DATE errors.
    // This is fine for a development deployment, but not a production environment -- the
    // SGX machines should be updated
    std::string isvEnclaveQuoteStatus = remove_surrounding_quotes(response["isvEnclaveQuoteStatus"].write());
    if (isvEnclaveQuoteStatus.compare("OK") != 0 &&
            isvEnclaveQuoteStatus.compare("GROUP_OUT_OF_DATE") != 0) {
        printf("isvEnclaveQuoteStatus invalid");
        return false;
    }

    // Get signed expected base64 enclave measurement for expected Teechain code
    char measurement[MAX_OCALL_RETURN_SIZE];
    int measurement_length;
    char signature[MAX_OCALL_RETURN_SIZE];
    int signature_length;
    ocall_get_signed_enclave_measurement(measurement, &measurement_length, signature, &signature_length);
    std::string expected_mrenclave(measurement, measurement_length);
    std::string mrenclave_signature(signature, signature_length);

    // Base64 decode Teechain signature
    std::string decoded_mrenclave_signature = decode_string(mrenclave_signature);

    // Decode the strings to be used
    std::string decoded_teechain_mrenclave_public_key_pem = decode_string(teechain_mrenclave_public_key_pem);

    // Verify Teechain measurement signature
    if (!verify_signature(expected_mrenclave, decoded_mrenclave_signature, decoded_teechain_mrenclave_public_key_pem)) {
        printf("Error: the expected measurement signature has been tampered with!");
	printf("Expected: %s", expected_mrenclave.c_str());
	printf("Expected signature: %s", mrenclave_signature.c_str());
	printf("Expected base64 decoded signature: %s", decoded_mrenclave_signature.c_str());
        return false;
    }

    // Base64 decode quote body
    std::string isvEnclaveQuoteBody = remove_surrounding_quotes(response["isvEnclaveQuoteBody"].write());

    // Extract given quote properties we need to check
    isvEnclaveQuoteBody = decode_string(isvEnclaveQuoteBody);
    int16_t* version = (int16_t*) isvEnclaveQuoteBody.c_str();
    std::string given_mrenclave(isvEnclaveQuoteBody.c_str() + 112, 32);
    given_mrenclave = encode_string(given_mrenclave);

    // Check IAS response version and enclave measurment match expected code measurement
    if (*version != 2 || expected_mrenclave != given_mrenclave) {
        printf("Enclave measurement or IAS version does not match expected values!");
        printf("Expected: %s\n", expected_mrenclave.c_str());
        printf("Given: %s\n", given_mrenclave.c_str());
        //return false;
    } else {
        printf("Intel Remote attestation passed!");
    }

    return true;
}

// Verify the given quote from the remote party by contacting the IAS.
static bool ias_verify_response(sample_quote_t* p_isv_quote,
                               uint8_t* pse_manifest,
                               ias_att_report_t* p_attestation_verification_report) {
    char response_signature[MAX_OCALL_RETURN_SIZE];
    int response_signature_len;
    char response_body[MAX_OCALL_RETURN_SIZE];
    int response_body_len;

    // Generate base64 encoded nonce
    std::string nonce = generate_random_nonce();
    nonce = encode_string(nonce);

    // Make ocall to get attestation report from IAS
    ocall_ias_get_attestation_evidence(p_isv_quote, pse_manifest, p_attestation_verification_report,
                                       nonce.c_str(), nonce.length(),
                                       response_signature, &response_signature_len,
                                       response_body, &response_body_len);

    std::string response_signature_str = std::string(response_signature, response_signature_len);
    std::string response_body_str = std::string(response_body, response_body_len);
    //TODO: check certificate chain returned by report is rooted in a trusted CA
    //TODO: check none of the certificates have been revoked

    // Decode the strings to be used
    std::string decoded_intel_ias_public_key_pem = decode_string(intel_ias_public_key_pem);

    // Verify signature
    if (!verify_signature(response_body_str, response_signature_str, decoded_intel_ias_public_key_pem)) {
        printf("Error: unable to verify response from IAS!");
        return false;
    }

    // Verify properties of response body such as nonce, enclave hash etc.
    if (!verify_response_quote(nonce, response_body_str)) {
        printf("Error: failed to verify response body! Quote response was not as expected!");
        return false;
    }

    // create attestation verification report using successful response from IAS
    // TODO(joshlind): for production make this include the actual values of a report that we
    // care about.
    p_attestation_verification_report->id = 1234567;
    p_attestation_verification_report->status = IAS_QUOTE_OK;
    p_attestation_verification_report->revocation_reason =
        IAS_REVOC_REASON_NONE;
    p_attestation_verification_report->info_blob.sample_epid_group_status =
        0 << IAS_EPID_GROUP_STATUS_REVOKED_BIT_POS
        | 0 << IAS_EPID_GROUP_STATUS_REKEY_AVAILABLE_BIT_POS;
    p_attestation_verification_report->info_blob.sample_tcb_evaluation_status =
        0 << IAS_TCB_EVAL_STATUS_CPUSVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_TCB_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS;
    p_attestation_verification_report->info_blob.pse_evaluation_status =
        0 << IAS_PSE_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_EPID_GROUP_REVOKED_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_PSDASVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_SIGRL_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_PRIVRL_OUT_OF_DATE_BIT_POS;
    memset(p_attestation_verification_report->
                info_blob.latest_equivalent_tcb_psvn, 0, PSVN_SIZE);
    memset(p_attestation_verification_report->info_blob.latest_pse_isvsvn,
           0, ISVSVN_SIZE);
    memset(p_attestation_verification_report->info_blob.latest_psda_svn,
           0, PSDA_SVN_SIZE);
    memset(p_attestation_verification_report->info_blob.performance_rekey_gid,
           0, GID_SIZE);

    return true;
}

// Simulates the attestation server function for verifying the quote produce by
// the ISV enclave. It doesn't decrypt or verify the quote in
// the simulation.  Just produces the attestaion verification
// report with the platform info blob.
//
// @param p_isv_quote Pointer to the quote generated by the ISV
//                    enclave.
// @param pse_manifest Pointer to the PSE manifest if used.
// @param p_attestation_verification_report Pointer the outputed
//                                          verification report.
//
// @return int

int ias_verify_attestation_evidence(
    sample_quote_t *p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* p_attestation_verification_report)
{
    int ret = 0;
    sgx_ecc_state_handle_t ecc_state = NULL;

    //unused parameters
    UNUSED(pse_manifest);

    if((NULL == p_isv_quote) ||
        (NULL == p_attestation_verification_report))
    {
        printf("Invalid arguments given to ias_verify_attestation_evidence");
        return -1;
    }
  
    // Decrypt the Quote signature and verify.
    // contact ias to verify the quote (outside enclave)
    if (!ias_verify_response(p_isv_quote, pse_manifest, p_attestation_verification_report)) {
        printf("Verification of IAS response failed!");
        return -1;
    }

    // @TODO: Product signing algorithm still TBD.  May be RSA2048 signing.
    // Generate the Service providers ECCDH key pair.
    do {
        ret = sgx_ecc256_open_context(&ecc_state);
        if (SGX_SUCCESS != ret) {
            printf("\nError, cannot get ECC cotext in [%s].",
                    __FUNCTION__);
            ret = -1;
            break;
        }
        // Sign
        ret = sgx_ecdsa_sign(
                (uint8_t *)&p_attestation_verification_report->
                    info_blob.sample_epid_group_status,
                sizeof(ias_platform_info_blob_t) - sizeof(sample_ec_sign256_t),
                (sgx_ec256_private_t *)&g_rk_priv_key,
                (sgx_ec256_signature_t *)&p_attestation_verification_report->
                    info_blob.signature,
                ecc_state);
        if (SGX_SUCCESS != ret) {
            printf("\nError, sign ga_gb fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        SWAP_ENDIAN_32B(p_attestation_verification_report->
                            info_blob.signature.x);
        SWAP_ENDIAN_32B(p_attestation_verification_report->
                            info_blob.signature.y);

    } while (0);

    if (ecc_state) {
        sgx_ecc256_close_context(ecc_state);
    }
    p_attestation_verification_report->pse_status = IAS_PSE_OK;

    // For now, don't simulate the policy reports.
    p_attestation_verification_report->policy_report_size = 0;
    return(ret);
}


// @param gid Group ID for the EPID key.
// @param p_sig_rl_size Pointer to the output value of the full
//                      SIGRL size in bytes. (including the
//                      signature).
// @param p_sig_rl Pointer to the output of the SIGRL.
//
// @return int

int ias_get_sigrl(
    const sample_epid_group_id_t gid,
    uint32_t *p_sig_rl_size,
    uint8_t *p_sig_rl)
{
    // contact ias for the signature revocation list (outside enclave)
    ocall_ias_get_sigrl((uint8_t*) gid, p_sig_rl_size, p_sig_rl);
    return 0;
}



// TODO: REMOVE -- ENROLLMENT HAPPENS OUT OF BAND (THIS FUNCTION IS NOT NEEDED)

// Used to simulate the enrollment function of an attestation server.  It only
// gives back the SPID right now. In production, the enrollment
// occurs out of context from an attestation attempt and only
// occurs once.
//
//
// @param sp_credentials
// @param p_spid
// @param p_authentication_token
//
// @return int

int ias_enroll(
    int sp_credentials,
    sample_spid_t *p_spid,
    int *p_authentication_token)
{
    UNUSED(sp_credentials);
    UNUSED(p_authentication_token);

    if (NULL != p_spid) {
        memcpy_s(p_spid, sizeof(sample_spid_t), SPID,
                 sizeof(sample_spid_t));
    } else {
        return(1);
    }
    return(0);
}


