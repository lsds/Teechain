#include "service_provider.h"
#include "ecp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include "ias_ra.h"
#include "teechain_u.h"
#include "teechain.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <cstdio>
#include <cstdlib>

#include <stdexcept>

#include "connection.h"
#include "restclient.h"
#include "json/json.h"

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "utils.h"

// Forward decls
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length);

// constants
#define INTEL_IAS_URL "TODO: provide valid Intel IAS URL"

#define INTEL_CERT "TODO: provide valid Intel IAS Certificate"

#define INTEL_KEY "TODO: provide valid intel IAS KEY"

static std::string intel_cert_file_name;
static std::string intel_key_file_name;

using namespace std;

// Encodes a string to base64
int Base64Encode(const char* message, int msg_len, char** buffer) {
  BIO *bio, *b64;
  FILE* stream;
  int encodedSize = 4*ceil((double) msg_len/3);
  *buffer = (char *)malloc(encodedSize+1);

  stream = fmemopen(*buffer, encodedSize+1, "w");
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines - write everything in one line
  BIO_write(bio, message, msg_len);
  BIO_flush(bio);
  BIO_free_all(bio);
  fclose(stream);

  return (0); //success
}

static std::string encode_string(std::string input) {
    char* input_encoded;
    Base64Encode(input.c_str(), input.length(), &input_encoded);
    return std::string(input_encoded);
}

static std::string decode_string(std::string input) {
    unsigned char* outbuf;
    size_t outlen;
    Base64Decode(input.c_str(), &outbuf, &outlen);
    return std::string((char*) outbuf, outlen);
}

static void write_to_file(std::string content_to_write, std::string path) {
    ofstream myfile;
    myfile.open (path);
    myfile << content_to_write;
}

static std::string generate_file_name() {
    /* generate secret number between 1 and 10: */
    int num = rand();

    // make this a little difficult to reverse engineer...
    return std::string("/t") + "m" + "p/" + std::to_string(num);
}

static std::string get_decoded(std::string input) {
    std::string decoded = decode_string(input);
    return decoded;
}

static void create_files() {
    /* initialize random seed: */
    srand(time(NULL));

    intel_cert_file_name = generate_file_name();
    intel_key_file_name = generate_file_name();

    write_to_file(get_decoded(INTEL_CERT), intel_cert_file_name);
    write_to_file(get_decoded(INTEL_KEY), intel_key_file_name);
}

static void delete_files() {
    std::remove(intel_cert_file_name.c_str());
    std::remove(intel_key_file_name.c_str());
}

// creates and returns an ias connection object
RestClient::Connection* get_ias_connection() {
    RestClient::init();
    RestClient::Connection* conn = new RestClient::Connection(get_decoded(INTEL_IAS_URL));

    conn->AppendHeader("Content-Type", "application/json");
    conn->SetCertPath(intel_cert_file_name);
    conn->SetKeyPath(intel_key_file_name);
    conn->SetCertType("PEM");

    return conn;
}

// contacts the IAS server to get the revocation list for the given group ID
int get_revocation_list(std::string gid, uint32_t *p_sig_rl_size, uint8_t *p_sig_rl) {
    create_files();
    RestClient::Connection* conn = get_ias_connection();

    std::string sigrl_rest_path = "/attestation/sgx/v2/sigrl/" + gid;
    RestClient::Response r = conn->get(sigrl_rest_path);
    delete_files();

    if (r.code != 200) {
        cerr << "Connection rest path: " << get_decoded(INTEL_IAS_URL) << sigrl_rest_path << endl;
        cerr << "Response: " << r.code << ", body: " << r.body << endl;
        cerr << "Response ID: " << r.headers["Request-ID"] << endl;
        return 1;
    } else {
        //print_important("Signature revocation list fetched successfully from IAS!");
    }

    if (r.body.empty()) {
        // empty revocation list
        *p_sig_rl_size = 0;
        p_sig_rl[0] = '\0';
    } else {
        *p_sig_rl_size = r.body.length();
        memcpy(p_sig_rl, r.body.c_str(), r.body.length() + 1);
    }

    RestClient::disable();
    return 0;
}

std::string get_base64_quote_from_isv_quote(sample_quote_t* p_isv_quote) {
    // get quote without signature
    int quote_without_signature_length = sizeof(sample_quote_t);
    std::string quote_without_signature((char*) p_isv_quote, quote_without_signature_length);

    // get signature
    int signature_length = p_isv_quote->signature_len;
    std::string signature((char*) p_isv_quote->signature, signature_length);

    // get entire quote and encoded to base64
    char* quote_encoded;
    int quote_length = quote_without_signature_length + signature_length;
    std::string quote = quote_without_signature + signature;
    Base64Encode(quote.c_str(), quote_length, &quote_encoded);

    return std::string(quote_encoded);
}

// Calculates the length of a decoded string
inline size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input),
        padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') {
        // last two chars are =
        padding = 2;
    } else if (b64input[len-1] == '=') {
        // last char is =
        padding = 1;
    }

    return (len*3)/4 - padding;
}

// Decodes a base64 encoded string
void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf((void*) b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));

    BIO_free_all(bio);
    if (*length != decodeLen) {
        throw std::runtime_error("Fatal error in decoding signature");
    }
}

// contacts the IAS server to verify the given quote
bool get_response_from_ias(sample_quote_t *p_isv_quote,
                           uint8_t* pse_manifest,  // unused
                           ias_att_report_t* p_attestation_verification_report,
                           const char* nonce,
                           int nonce_len,
                           char* response_signature,
                           int* response_signature_len,
                           char* response_body,
                           int* response_body_len) {

    std::string quote_rest_path = "/attestation/sgx/v2/report";
    std::string quote_base64 = get_base64_quote_from_isv_quote(p_isv_quote);
    std::string nonce_str(nonce, nonce_len);
    string att_evidence_payload = "{\"isvEnclaveQuote\": \"" + quote_base64 + "\","+
                                   "\"nonce\": \"" + nonce_str + "\"}";

    // make request to IAS
    create_files();
    RestClient::Connection* conn = get_ias_connection();
    RestClient::Response r = conn->post(quote_rest_path, att_evidence_payload);
    delete_files();

    if (r.code != 200) {
        cerr << "Connection rest path: " << quote_rest_path << endl;
        cerr << "Given payload: " << att_evidence_payload << endl;
        cerr << "Response: " << r.code << ", body: " << r.body << endl;
        cerr << "Response ID: " << r.headers["Request-ID"] << endl;
        cerr << "Quote verification failed!" << endl;
        return false;
    }

    // output quote and response for debugging
//    print_important("Quote Given to IAS:");
//    print_important(quote_base64);    
//    print_important("Response from IAS:"); 
//    print_important(r.body);
    RestClient::disable();

    // return signature
    unsigned char* sigbuf;
    size_t siglen;
    std::string response_signature_str = r.headers["x-iasreport-signature"];
    Base64Decode(response_signature_str.c_str(), &sigbuf, &siglen);
    *response_signature_len = siglen;
    std::memcpy(response_signature, sigbuf, siglen);
    free(sigbuf);

    // return body
    std::string response_body_str = r.body;
    *response_body_len = response_body_str.length();
    std::memcpy(response_body, response_body_str.c_str(), *response_body_len); 
    return true;
}

// @param gid Group ID for the EPID key.
// @param p_sig_rl_size Pointer to the output value of the full
//                      SIGRL size in bytes. (including the
//                      signature).
// @param p_sig_rl Pointer to the output of the SIGRL.
//
// @return int
void ocall_ias_get_sigrl(
    uint8_t* gid,
    uint32_t *p_sig_rl_size,
    uint8_t *p_sig_rl)
{
    std::stringstream gid_ss; // gid format needs to be in big endian for IAS
    gid_ss << std::hex << std::setfill('0');

    for (int i = 3; i >= 0; i--) {
        gid_ss << std::setw(2) << static_cast<unsigned>(gid[i]);
    }
    
    if (get_revocation_list(gid_ss.str(), p_sig_rl_size, p_sig_rl) != 0) {
        printf("get_revocation_list failed!");
        exit(0); // ias contact failed -- exit
    }
}

// @param p_isv_quote Pointer to the quote generated by the ISV
//                    enclave.
// @param pse_manifest Pointer to the PSE manifest if used.
// @param p_attestation_verification_report Pointer the outputed
//                                          verification report.
//
// @return int
void ocall_ias_get_attestation_evidence(
    sample_quote_t *p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* p_attestation_verification_report,
    const char* nonce,
    int nonce_len,
    char* response_signature,
    int* response_signature_len,
    char* response_body,
    int* response_body_len)
{
    if((NULL == p_isv_quote) ||
        (NULL == p_attestation_verification_report)) {
        printf("invalid memory arguments given to ocall_ias_get_attestation_evidence");
    }

    if (!get_response_from_ias(p_isv_quote, pse_manifest, p_attestation_verification_report, nonce, nonce_len, response_signature,
            response_signature_len, response_body, response_body_len) != 0) {
        printf("get_response_from_ias!");
        exit(0);
    }
}

void ocall_get_signed_enclave_measurement(char* measurement, int* measurement_length, char* signature, int* signature_length) {
    std::string signed_measurement = "TODO: provide expected enclave MRENCLAVE measurement";
    std::string signature_measurement = "TODO: provide valid signature over expected MRENCLAVE measurement";

    // return measurement and length to enclave  
    *measurement_length = signed_measurement.length();
    memcpy(measurement, signed_measurement.c_str(), *measurement_length);

    *signature_length = signature_measurement.length();
    memcpy(signature, signature_measurement.c_str(), *signature_length);
}
