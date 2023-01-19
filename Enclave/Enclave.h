/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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

#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <assert.h>
#include <stdlib.h>
#include <sgx_tcrypto.h>
#include <sgx_key_exchange.h>
#include <sgx_spinlock.h>

typedef enum _ra_state
{
    ra_inited= 0,
    ra_get_gaed,
    ra_proc_msg2ed
}ra_state;

typedef struct _ra_db_item_t
{
    sgx_ec256_public_t          g_a;
    sgx_ec256_public_t          g_b;
    sgx_ec_key_128bit_t         vk_key;
    sgx_ec256_public_t          sp_pubkey;
    sgx_ec256_private_t         a;
    sgx_ps_sec_prop_desc_t      ps_sec_prop;
    sgx_ec_key_128bit_t         mk_key;
    sgx_ec_key_128bit_t         sk_key;
    sgx_ec_key_128bit_t         smk_key;
    sgx_quote_nonce_t           quote_nonce;
    sgx_target_info_t           qe_target; 
    ra_state                    state;
    sgx_spinlock_t              item_lock;
    uintptr_t                   derive_key_cb;
} ra_db_item_t;


#if defined(__cplusplus)
extern "C" {
#endif

int printf(const char* fmt, ...);
//void find_min_change(size_t ***X,size_t **len,size_t n,size_t n_bucket);
void msi(size_t ***X,size_t **len,size_t *out,size_t n,size_t len_min,size_t n_bucket);


#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
