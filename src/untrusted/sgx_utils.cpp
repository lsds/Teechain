#include "teechain.h"

// SGX Error List
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

// safer memcpy
errno_t memcpy_s(void *dest, size_t num_elements, const void *src, size_t count) {
    if (num_elements < count) return -1;
    memcpy(dest, src, count);
    return 0;
}

/* Check error conditions for loading enclave */
void print_sgx_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(void *mem, uint32_t len) {
    if(!mem || !len)
    {
        printf("\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    printf("%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        printf("0x%x, ", array[i]);
        if(i % 8 == 7) printf("\n");
    }
    printf("0x%x ", array[i]);
    printf("\n}\n");
}

void PRINT_ATTESTATION_SERVICE_RESPONSE(ra_samp_response_header_t *response) {
    if(!response)
    {
        printf("\t\n( null )\n");
        return;
    }

    printf("RESPONSE TYPE:   0x%x\n", response->type);
    printf("RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    printf("RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        printf("MSG2 gb - ");
        PRINT_BYTE_ARRAY(&(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        printf("MSG2 spid - ");
        PRINT_BYTE_ARRAY(&(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        printf("MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        printf("MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        printf("MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(&(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        printf("MSG2 mac - ");
        PRINT_BYTE_ARRAY(&(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        printf("MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(&(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        printf("ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(&(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        printf("ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(&(p_att_result->mac), sizeof(p_att_result->mac));

        printf("ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        printf("ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        printf("\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
}
