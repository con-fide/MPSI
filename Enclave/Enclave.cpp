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
#include "../App/Tools/config.h"

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include  <stdarg.h>
#include  <stdio.h> /* vsnprintf */
#include  <string.h>
#include  <algorithm>
#include  <math.h>
#include  <thread>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
// int printf(const char* fmt, ...)
// {
//     char buf[BUFSIZ] = { '\0' };
//     va_list ap;
//     va_start(ap, fmt);
//     vsnprintf(buf, BUFSIZ, fmt, ap);
//     va_end(ap);
//     ocall_print_string(buf);
//     return (int)strnlen(buf, BUFSIZ - 1) + 1;
// }

/*
* @Functionality: 快速幂
*/
size_t Pow(size_t x,size_t y,size_t p){
	size_t res=1;
	while(y){
		if(y&1)
			res=(1LL*res*x)%p;
		y>>=1;
		x=(1LL*x*x)%p;
	}
	return res;
}


/*
* @Functionality: given $(len_min)'s set X[i], each with size of len[i]
*				  compute the intersection among them and store the result in array y
*
* @Iner-Params:
*		@z indicator vector with size of len[0]
*		@y vector storing the intermediate set intersection result
*		@p hard-coded big prime with 33 bits, with presuppose that each element is 32 bits
*/
// void msi(size_t **X,size_t *len,size_t *y,size_t n,size_t len_min)
// {
// 	/*
// 	*	variable initialization part
// 	*/
// 	size_t z[len[0]];
// 	for(size_t i=0; i<len[0]; i++){
// 		y[i]=X[0][i];
// 		z[i]=0;
// 	}

// 	size_t p=4011284869; 
// 	size_t q=p-1;
// 	size_t a=1;
	
	
// 	*	core computation part
	
// 	for(size_t k=1;k<n;k++)
// 	{
// 		for(size_t i=0;i<len[0];i++)
// 		{	
// 			a = 1;
// 			for(size_t j=0;j<len[k];j++)
// 			{
// 				a = abs((X[k][j]-y[i]))*a;
// 				a = a%p;
// 			}		
// 			z[i] = Pow(a,q,p);
// 			y[i] = y[i]*(1 - z[i]);
// 		}
// 	}

// }

/*called from SGX find the min len for each bucket and change it to the first place*/
// void find_min_change(size_t ***X,size_t **len,size_t n,size_t n_bucket)
// {
// 	for(int t=0;t<n_bucket;t++)
// 	{
// 		size_t min_pos = 0;
// 		for(size_t i=1; i<n; i++){
// 			if(len[i][t] < len[min_pos][t]){
// 				min_pos = i;
// 			}
// 		}
		
// 		/*	test output code, comment in non-debug state*/
		
// 		if(min_pos){
// 	     	size_t *temp;
// 	     	size_t temp_l;
	        
// 	     	temp=X[0][t];
// 	     	X[0][t]=X[min_pos][t];
// 	     	X[min_pos][t]=temp;

// 	     	temp_l=len[0][t];
// 	     	len[0][t]=len[min_pos][t];
// 	     	len[min_pos][t]=temp_l;     
// 	    }
// 	}
// }


void corecomputation()
{
	    //printf("hello thread \n");
}

void msi(size_t ***X,size_t **len,size_t *out,size_t n,size_t len_min,size_t n_bucket)
{
	/*
	*	variable initialization part
	*/
	size_t a=1, b;
	//printf("I reach the enclave program now!!!\n");

	/*
	*	core computation part
	*/

	size_t sum_len=0;
	// size_t **y=new size_t *[n_bucket];
	for(int t=0;t<n_bucket;t++)            //对于所有用户的同一个桶（第一个桶），yi初始化为第一个用户这个桶（第一个桶）里的元素，先和它比
	{

		//find_min_change(X,len,n,n_bucket);
		size_t min_bucket=len[0][t];
		//size_t *y=new size_t[min_bucket];
		size_t y[min_bucket];

		// for(int i=0;i<n_bucket;i++)
		// 	y[i]=new size_t[min_bucket];


		for(size_t i=0; i<min_bucket; i++)
		{
			y[i] = X[0][t][i];
		}


		for(size_t k=1;k<n;k++)				//第二个用户该桶号（第一个桶）内的所有元素的y做差，看是否有0 
		{
			for(size_t i=0;i<min_bucket;i++)
			{	
				a= 1;
				for(size_t j=0;j<len[k][t];j++)
				{
					b = (X[k][t][j] ^ y[i]);
					b = (b >> 32) | ((b << 32) >> 32);
				    b = (b >> 16) | ((b << 48) >> 48);
				    b = (b >> 8)  | ((b << 56) >> 56);
				    b = (b >> 4)  | ((b << 60) >> 60);
				    b = (b >> 2)  | ((b << 62) >> 62);
				    b = (b >> 1)  | ((b << 63) >> 63);
				    a = a & b;
				}		
				y[i] = y[i]*(1 - a);				//这一组里有0,yi就会保存下所有用户该桶号里相同的元素
			}
		}
		for(int i=0;i<min_bucket;i++)
		{
			out[sum_len+i]=y[i];
			//printf("out[%d]:%d",i,y[i]);
		}

		sum_len+=min_bucket;


	}


	// int samenumber=0;
 //    for(size_t i=0;i<len_min;i++)
 //    {
 //        if(out[i]!=0)
 //            samenumber++;
 //        printf("out[%d]%d ",i,out[i]);
 //    }
 //    printf("\n[INFO] outer intersection result :%d\n",samenumber);


}

/***************************************************Start Attestation Part****************************************************************/
static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}

size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_close_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

/***************************************************End Attestation Part****************************************************************/

