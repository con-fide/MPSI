// (C) 2019 University of NKU. Free for used
// Author: stoneboat@mail.nankai.edu.cn

/*
* server_core.cpp
*
*/

#include "server_core.h"
#include "../Tools/ezOptionParser.h"
#include "../Exceptions/Exceptions.h"
#include "../Networking/sockets.h"
#include "../Networking/data.h"
#include "../Tools/utils.h"

using namespace std;

#include "../Tools/config.h"
# include "../Enclave_u.h"
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "../CTools/sgx_stub.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/des.h>

#include <getopt.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "../Tools/common.h"
#include "../Tools/protocol.h"
#include "../CTools/sgx_detect.h"
#include "../CTools/hexutil.h"
#include "../CTools/fileio.h"
#include "../CTools/base64.h"
#include "../CTools/crypto.h"
#include "../Tools/msgio.h"
#include "../CTools/logfile.h"
#include "../CTools/quote_size.h"

#include <iostream>
#include <fstream> 
#include <string>
#include <string.h>

/*----------------client.cpp start---------------------*/
#define MAX_LEN 80


# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
    char mode;
    uint32_t flags;
    sgx_spid_t spid;
    sgx_ec256_public_t pubkey;
    sgx_quote_nonce_t nonce;
    char *server;
    char *port;
} config_t;

int file_in_searchpath (const char *file, const char *search, char *fullpath,
    size_t len);

sgx_status_t sgx_create_enclave_search (
    const char *filename,
    const int edebug,
    sgx_launch_token_t *token,
    int *updated,
    sgx_enclave_id_t *eid,
    sgx_misc_attribute_t *attr
);

void usage();
int do_quote(sgx_enclave_id_t eid, config_t *config);
int do_attestation(sgx_enclave_id_t eid, config_t *config);

// char debug= 0;
// char verbose= 0;
//extern int att;

#define MODE_ATTEST 0x0
#define MODE_EPID   0x1
#define MODE_QUOTE  0x2

#define OPT_PSE     0x01
#define OPT_NONCE   0x02
#define OPT_LINK    0x04
#define OPT_PUBKEY  0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)    x|=y
#define CLEAR_OPT(x,y)  x=x&~y
#define OPT_ISSET(x,y)  x&y


# define ENCLAVE_NAME "enclave.signed.so"


int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
    sgx_status_t status, sgxrv, pse_status;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t *msg2 = NULL;
    sgx_ra_msg3_t *msg3 = NULL;
    ra_msg4_t *msg4 = NULL;
    uint32_t msg0_extended_epid_group_id = 0;
    uint32_t msg3_sz;
    uint32_t flags= config->flags;
    sgx_ra_context_t ra_ctx= 0xdeadbeef;
    int rv;
    MsgIO *msgio;
    size_t msg4sz = 0;
    int enclaveTrusted = NotTrusted; // Not Trusted
    int b_pse= OPT_ISSET(flags, OPT_PSE);

    if ( config->server == NULL ) {
        msgio = new MsgIO();
    } else {
        try {
            msgio = new MsgIO(config->server, (config->port == NULL) ?
                DEFAULT_PORT : config->port);
        }
        catch(...) {
            exit(1);
        }
    }

    /*
     * WARNING! Normally, the public key would be hardcoded into the
     * enclave, not passed in as a parameter. Hardcoding prevents
     * the enclave using an unauthorized key.
     *
     * This is diagnostic/test application, however, so we have
     * the flexibility of a dynamically assigned key.
     */

    /* Executes an ECALL that runs sgx_ra_init() */

    if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
        if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
        status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
            &ra_ctx, &pse_status);
    } else {
        if ( debug ) fprintf(stderr, "+++ using default public key\n");
        status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
            &pse_status);
    }

    /* Did the ECALL succeed? */
    if ( status != SGX_SUCCESS ) {
        fprintf(stderr, "enclave_ra_init: %08x\n", status);
        delete msgio;
        return 1;
    }

    /* If we asked for a PSE session, did that succeed? */
    if (b_pse) {
        if ( pse_status != SGX_SUCCESS ) {
            fprintf(stderr, "pse_session: %08x\n", sgxrv);
            delete msgio;
            return 1;
        }
    }

    /* Did sgx_ra_init() succeed? */
    if ( sgxrv != SGX_SUCCESS ) {
        fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
        delete msgio;
        return 1;
    }

    /* Generate msg0 */

    status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
    if ( status != SGX_SUCCESS ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx); 
        fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
        delete msgio;
        return 1;
    }
    if ( verbose ) {
        dividerWithText(stderr, "Msg0 Details");
        dividerWithText(fplog, "Msg0 Details");
        fprintf(stderr,   "Extended Epid Group ID: ");
        fprintf(fplog,   "Extended Epid Group ID: ");
        print_hexstring(stderr, &msg0_extended_epid_group_id,
             sizeof(uint32_t));
        print_hexstring(fplog, &msg0_extended_epid_group_id,
             sizeof(uint32_t));
        fprintf(stderr, "\n");
        fprintf(fplog, "\n");
        divider(stderr);
        divider(fplog);
    }
 
    /* Generate msg1 */

    //status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
    if ( status != SGX_SUCCESS ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
        fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
        delete msgio;
        return 1;
    }

    if ( verbose ) {
        dividerWithText(stderr,"Msg1 Details");
        dividerWithText(fplog,"Msg1 Details");
        fprintf(stderr,   "msg1.g_a.gx = ");
        fprintf(fplog,   "msg1.g_a.gx = ");
        print_hexstring(stderr, msg1.g_a.gx, 32);
        print_hexstring(fplog, msg1.g_a.gx, 32);
        fprintf(stderr, "\nmsg1.g_a.gy = ");
        fprintf(fplog, "\nmsg1.g_a.gy = ");
        print_hexstring(stderr, msg1.g_a.gy, 32);
        print_hexstring(fplog, msg1.g_a.gy, 32);
        fprintf(stderr, "\nmsg1.gid    = ");
        fprintf(fplog, "\nmsg1.gid    = ");
        print_hexstring(stderr, msg1.gid, 4);
        print_hexstring(fplog, msg1.gid, 4);
        fprintf(stderr, "\n");
        fprintf(fplog, "\n");
        divider(stderr);
        divider(fplog);
    }

    /*
     * Send msg0 and msg1 concatenated together (msg0||msg1). We do
     * this for efficiency, to eliminate an additional round-trip
     * between client and server. The assumption here is that most
     * clients have the correct extended_epid_group_id so it's
     * a waste to send msg0 separately when the probability of a
     * rejection is astronomically small.
     *
     * If it /is/ rejected, then the client has only wasted a tiny
     * amount of time generating keys that won't be used.
     */

    dividerWithText(fplog, "Msg0||Msg1 ==> SP");
    fsend_msg_partial(fplog, &msg0_extended_epid_group_id,
        sizeof(msg0_extended_epid_group_id));
    fsend_msg(fplog, &msg1, sizeof(msg1));
    divider(fplog);

    dividerWithText(stderr, "Copy/Paste Msg0||Msg1 Below to SP");
    msgio->send_partial(&msg0_extended_epid_group_id,
        sizeof(msg0_extended_epid_group_id));
    msgio->send(&msg1, sizeof(msg1));
    divider(stderr);

    fprintf(stderr, "Waiting for msg2\n");

    /* Read msg2 
     *
     * msg2 is variable length b/c it includes the revocation list at
     * the end. msg2 is malloc'd in readZ_msg do free it when done.
     */

    rv= msgio->read((void **) &msg2, NULL);
    if ( rv == 0 ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "protocol error reading msg2\n");
        delete msgio;
        exit(1);
    } else if ( rv == -1 ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "system error occurred while reading msg2\n");
        delete msgio;
        exit(1);
    }

    if ( verbose ) {
        dividerWithText(stderr, "Msg2 Details");
        dividerWithText(fplog, "Msg2 Details (Received from SP)");
        fprintf(stderr,   "msg2.g_b.gx      = ");
        fprintf(fplog,   "msg2.g_b.gx      = ");
        print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
        print_hexstring(fplog, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
        fprintf(stderr, "\nmsg2.g_b.gy      = ");
        fprintf(fplog, "\nmsg2.g_b.gy      = ");
        print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
        print_hexstring(fplog, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
        fprintf(stderr, "\nmsg2.spid        = ");
        fprintf(fplog, "\nmsg2.spid        = ");
        print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
        print_hexstring(fplog, &msg2->spid, sizeof(msg2->spid));
        fprintf(stderr, "\nmsg2.quote_type  = ");
        fprintf(fplog, "\nmsg2.quote_type  = ");
        print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
        print_hexstring(fplog, &msg2->quote_type, sizeof(msg2->quote_type));
        fprintf(stderr, "\nmsg2.kdf_id      = ");
        fprintf(fplog, "\nmsg2.kdf_id      = ");
        print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
        print_hexstring(fplog, &msg2->kdf_id, sizeof(msg2->kdf_id));
        fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
        fprintf(fplog, "\nmsg2.sign_ga_gb  = ");
        print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
        print_hexstring(fplog, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
        fprintf(stderr, "\nmsg2.mac         = ");
        fprintf(fplog, "\nmsg2.mac         = ");
        print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
        print_hexstring(fplog, &msg2->mac, sizeof(msg2->mac));
        fprintf(stderr, "\nmsg2.sig_rl_size = ");
        fprintf(fplog, "\nmsg2.sig_rl_size = ");
        print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
        print_hexstring(fplog, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
        fprintf(stderr, "\nmsg2.sig_rl      = ");
        fprintf(fplog, "\nmsg2.sig_rl      = ");
        print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
        print_hexstring(fplog, &msg2->sig_rl, msg2->sig_rl_size);
        fprintf(stderr, "\n");
        fprintf(fplog, "\n");
        divider(stderr);
        divider(fplog);
    }

    if ( debug ) {
        fprintf(stderr, "+++ msg2_size = %zu\n",
            sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
        fprintf(fplog, "+++ msg2_size = %zu\n",
            sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
    }

    /* Process Msg2, Get Msg3  */
    /* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

    msg3 = NULL;

    // status = sgx_ra_proc_msg2(ra_ctx, eid,
    //     sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
    //     sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
    //     &msg3, &msg3_sz);

    free(msg2);

    if ( status != SGX_SUCCESS ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
        fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

        delete msgio;
        return 1;
    } 

    if ( debug ) {
        fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
        fprintf(fplog, "+++ msg3_size = %u\n", msg3_sz);
    }
                              
    if ( verbose ) {
        dividerWithText(stderr, "Msg3 Details");
        dividerWithText(fplog, "Msg3 Details");
        fprintf(stderr,   "msg3.mac         = ");
        fprintf(fplog,   "msg3.mac         = ");
        print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
        print_hexstring(fplog, msg3->mac, sizeof(msg3->mac));
        fprintf(stderr, "\nmsg3.g_a.gx      = ");
        fprintf(fplog, "\nmsg3.g_a.gx      = ");
        print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
        print_hexstring(fplog, msg3->g_a.gx, sizeof(msg3->g_a.gx));
        fprintf(stderr, "\nmsg3.g_a.gy      = ");
        fprintf(fplog, "\nmsg3.g_a.gy      = ");
        print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
        print_hexstring(fplog, msg3->g_a.gy, sizeof(msg3->g_a.gy));
        fprintf(stderr, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
        fprintf(fplog, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
        print_hexstring(stderr, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
            sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
        print_hexstring(fplog, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
            sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
        fprintf(fplog, "\n");
        fprintf(stderr, "\nmsg3.quote       = ");
        fprintf(fplog, "\nmsg3.quote       = ");
        print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
        print_hexstring(fplog, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
        fprintf(fplog, "\n");
        fprintf(stderr, "\n");
        fprintf(fplog, "\n");
        divider(stderr);
        divider(fplog);
    }

    dividerWithText(stderr, "Copy/Paste Msg3 Below to SP");
    msgio->send(msg3, msg3_sz);
    divider(stderr);

    dividerWithText(fplog, "Msg3 ==> SP");
    fsend_msg(fplog, msg3, msg3_sz);
    divider(fplog);

    if ( msg3 ) {
        free(msg3);
        msg3 = NULL;
    }
 
    /* Read Msg4 provided by Service Provider, then process */
        
    rv= msgio->read((void **)&msg4, &msg4sz);
    if ( rv == 0 ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "protocol error reading msg4\n");
        delete msgio;
        exit(1);
    } else if ( rv == -1 ) {
        enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "system error occurred while reading msg4\n");
        delete msgio;
        exit(1);
    }

    edividerWithText("Enclave Trust Status from Service Provider");

    enclaveTrusted= msg4->status;

    // int att;
    if ( enclaveTrusted == Trusted ) {
        eprintf("Enclave TRUSTED\n");
        //att=1;
    }
    else if ( enclaveTrusted == NotTrusted ) {
        eprintf("Enclave NOT TRUSTED\n");
        //att=0;
    }
    else if ( enclaveTrusted == Trusted_ItsComplicated ) {
        // Trusted, but client may be untrusted in the future unless it
        // takes action.

        eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
        //att=1;
    } else {
        // Not Trusted, but client may be able to take action to become
        // trusted.

        eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
        //att=1;
    }
    //printf("----%d\n",att );

    /* check to see if we have a PIB by comparing to empty PIB */
    sgx_platform_info_t emptyPIB;
    memset(&emptyPIB, 0, sizeof (sgx_platform_info_t));

    int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof (sgx_platform_info_t));

    if (retPibCmp == 0 ) {
        if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
    } else {
        if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

        if ( debug )  {
            eprintf("+++ PIB: " );
            print_hexstring(stderr, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
            print_hexstring(fplog, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
            eprintf("\n");
        }

        /* We have a PIB, so check to see if there are actions to take */
        sgx_update_info_bit_t update_info;
        sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
            enclaveTrusted, &update_info);

        if ( debug )  eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);

        edivider();

        /* Check to see if there is an update needed */
        if ( ret == SGX_ERROR_UPDATE_NEEDED ) {

            edividerWithText("Platform Update Required");
            eprintf("The following Platform Update(s) are required to bring this\n");
            eprintf("platform's Trusted Computing Base (TCB) back into compliance:\n\n");
            if( update_info.pswUpdate ) {
                eprintf("  * Intel SGX Platform Software needs to be updated to the latest version.\n");
            }

            if( update_info.csmeFwUpdate ) {
                eprintf("  * The Intel Management Engine Firmware Needs to be Updated.  Contact your\n");
                eprintf("    OEM for a BIOS Update.\n");
            }

            if( update_info.ucodeUpdate )  {
                eprintf("  * The CPU Microcode needs to be updated.  Contact your OEM for a platform\n");
                eprintf("    BIOS Update.\n");
            }                                           
            eprintf("\n");
            edivider();      
        }
    }

    /*
     * If the enclave is trusted, fetch a hash of the the MK and SK from
     * the enclave to show proof of a shared secret with the service 
     * provider.
     */

    if ( enclaveTrusted == Trusted ) {
        sgx_status_t key_status, sha_status;
        sgx_sha256_hash_t mkhash, skhash;

        // First the MK

        if ( debug ) eprintf("+++ fetching SHA256(MK)\n");
        status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
            SGX_RA_KEY_MK, &mkhash);
        if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
            status);

        if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
        // Then the SK

        if ( debug ) eprintf("+++ fetching SHA256(SK)\n");
        status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
            SGX_RA_KEY_SK, &skhash);
        if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
            status);

        if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
        if ( verbose ) {
            eprintf("SHA256(MK) = ");
            print_hexstring(stderr, mkhash, sizeof(mkhash));
            print_hexstring(fplog, mkhash, sizeof(mkhash));
            eprintf("\n");
            eprintf("SHA256(SK) = ");
            print_hexstring(stderr, skhash, sizeof(skhash));
            print_hexstring(fplog, skhash, sizeof(skhash));
            eprintf("\n");
        }
    }

    free (msg4);

    enclave_ra_close(eid, &sgxrv, ra_ctx);
    delete msgio;

    return 0;
}

/*----------------------------------------------------------------------
 * do_quote()
 *
 * Generate a quote from the enclave.
 *----------------------------------------------------------------------
 * WARNING!
 *
 * DO NOT USE THIS SUBROUTINE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. do_quote() short-circuits the RA process in order 
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation: 
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_calc_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */

int do_quote(sgx_enclave_id_t eid, config_t *config)
{
    sgx_status_t status, sgxrv;
    sgx_quote_t *quote;
    sgx_report_t report;
    sgx_report_t qe_report;
    sgx_target_info_t target_info;
    sgx_epid_group_id_t epid_gid;
    uint32_t sz= 0;
    uint32_t flags= config->flags;
    sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
    sgx_ps_cap_t ps_cap;
    char *pse_manifest = NULL;
    size_t pse_manifest_sz;

    char  *b64quote= NULL;
    char *b64manifest = NULL;


    if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;

    /* Platform services info */
    if (OPT_ISSET(flags, OPT_PSE)) {
        status = get_pse_manifest_size(eid, &pse_manifest_sz);
        if (status != SGX_SUCCESS) {
            fprintf(stderr, "get_pse_manifest_size: %08x\n",
                status);
            return 1;
        }

        pse_manifest = (char *) malloc(pse_manifest_sz);

        status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
        if (status != SGX_SUCCESS) {
            fprintf(stderr, "get_pse_manifest: %08x\n",
                status);
            return 1;
        }
        if (sgxrv != SGX_SUCCESS) {
            fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
                sgxrv);
            return 1;
        }
    }

    /* Get our quote */

    memset(&report, 0, sizeof(report));

    status= sgx_init_quote(&target_info, &epid_gid);
    if ( status != SGX_SUCCESS ) {
        fprintf(stderr, "sgx_init_quote: %08x\n", status);
        return 1;
    }

    /* Did they ask for just the EPID? */
    if ( config->mode == MODE_EPID ) {
        printf("%08x\n", *(uint32_t *)epid_gid);
        exit(0);
    }

    status= get_report(eid, &sgxrv, &report, &target_info);
    if ( status != SGX_SUCCESS ) {
        fprintf(stderr, "get_report: %08x\n", status);
        return 1;
    }
    if ( sgxrv != SGX_SUCCESS ) {
        fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
        return 1;
    }

    // sgx_get_quote_size() has been deprecated, but our PSW may be too old
    // so use a wrapper function.

    if (! get_quote_size(&status, &sz)) {
        fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
        return 1;
    }
    if ( status != SGX_SUCCESS ) {
        fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
        return 1;
    }

    quote= (sgx_quote_t *) malloc(sz);
    if ( quote == NULL ) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    memset(quote, 0, sz);
    status= sgx_get_quote(&report, linkable, &config->spid,
        (OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
        NULL, 0,
        (OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
        quote, sz);
    if ( status != SGX_SUCCESS ) {
        fprintf(stderr, "sgx_get_quote: %08x\n", status);
        return 1;
    }

    /* Print our quote */


    b64quote= base64_encode((char *) quote, sz);
    if ( b64quote == NULL ) {
        eprintf("Could not base64 encode quote\n");
        return 1;
    }

    if (OPT_ISSET(flags, OPT_PSE)) {
        b64manifest= base64_encode((char *) pse_manifest, pse_manifest_sz);
        if ( b64manifest == NULL ) {
            free(b64quote);
            eprintf("Could not base64 encode manifest\n");
            return 1;
        }
    }


    printf("{\n");
    printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
    if ( OPT_ISSET(flags, OPT_NONCE) ) {
        printf(",\n\"nonce\":\"");
        print_hexstring(stdout, &config->nonce, 16);
        printf("\"");
    }

    if (OPT_ISSET(flags, OPT_PSE)) {
        printf(",\n\"pseManifest\":\"%s\"", b64manifest);   
    }
    printf("\n}\n");

#ifdef SGX_HW_SIM
    fprintf(stderr, "WARNING! Built in h/w simulation mode. This quote will not be verifiable.\n");
#endif

    free(b64quote);
    if ( b64manifest != NULL ) free(b64manifest);

    return 0;

}

/*
 * Search for the enclave file and then try and load it.
 */


sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
    sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
    sgx_misc_attribute_t *attr)
{
    struct stat sb;
    char epath[PATH_MAX];   /* includes NULL */

    /* Is filename an absolute path? */

    if ( filename[0] == '/' ) 
        return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

    /* Is the enclave in the current working directory? */

    if ( stat(filename, &sb) == 0 )
        return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

    /* Search the paths in LD_LBRARY_PATH */

    if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
        
    /* Search the paths in DT_RUNPATH */

    if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

    /* Standard system library paths */

    if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
        return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

    /*
     * If we've made it this far then we don't know where else to look.
     * Just call sgx_create_enclave() which assumes the enclave is in
     * the current working directory. This is almost guaranteed to fail,
     * but it will insure we are consistent about the error codes that
     * get reported to the calling function.
     */

    return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
    size_t len)
{
    char *p, *str;
    size_t rem;
    struct stat sb;

    if ( search == NULL ) return 0;
    if ( strlen(search) == 0 ) return 0;

    str= strdup(search);
    if ( str == NULL ) return 0;

    p= strtok(str, ":");
    while ( p != NULL) {
        size_t lp= strlen(p);

        if ( lp ) {

            strncpy(fullpath, p, len-1);
            rem= (len-1)-lp-1;
            fullpath[len-1]= 0;

            strncat(fullpath, "/", rem);
            --rem;

            strncat(fullpath, file, rem);

            if ( stat(fullpath, &sb) == 0 ) {
                free(str);
                return 1;
            }
        }

        p= strtok(NULL, ":");
    }

    free(str);

    return 0;
}




void usage () 
{
    fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
    fprintf(stderr, "Required:\n");
    fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
    fprintf(stderr, "                             ASCII hex string\n");
    fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
    fprintf(stderr, "                             provider.\n");
    fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
    fprintf(stderr, "                             ASCII hex string\n");
    fprintf(stderr, "  -d, --debug              Show debugging information\n");
    fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
    fprintf(stderr, "                             an attestation.\n");
    fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
    fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
    fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
    fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
    fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
    fprintf(stderr, "                             default.\n");
    fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
    fprintf(stderr, "                             attestation.\n");
    fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
    fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
    fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
    fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
    fprintf(stderr, "                             connecting to a server.\n");
    fprintf(stderr, "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
    exit(1);
}

/*----------------client.cpp end---------------------*/

server_core::server_core(int argc, const char** argv,size_t **X,size_t *len){
	ez::ezOptionParser opt;

    opt.syntax = "./server.x -nt 1 -pn 5000\n";
    opt.add(
        "", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "Directory containing the server data (default: Server_Storage)", // Help description.
        "-d", // Flag token.
        "--dir" // Flag token.
    );
    opt.add(
        "1", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of the threads(default 1)", // Help description.
        "-nt", // Flag token.
        "--number_threads" // Flag token.
    );
    opt.add(
      "5000", // Default.
      0, // Required?
      1, // Number of args expected.
      0, // Delimiter if expecting multiple args.
      "Port number base to attempt to start connections from (default: 5000)", // Help description.
      "-pn", // Flag token.
      "--portnumbase" // Flag token.
    );
    opt.add(
        "2", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "number of parties (default: 2)", // Help description.
        "-np", // Flag token.
        "--n_parties" // Flag token.
    );

    opt.parse(argc, argv);

    opt.get("--number_threads")->getInt(nthreads);
    opt.get("--portnumbase")->getInt(pnbase);
    opt.get("--n_parties")->getInt(nclients);


    

    
    if (opt.isSet("--dir"))
    {
        opt.get("--dir")->getString(PREP_DATA_PREFIX);
        PREP_DATA_PREFIX += "/";
    }
    else{
        PREP_DATA_PREFIX = "Server_Storage/";
    }

    /*
    *	create the local data folder if it is not exists
    */
    if(!is_directory(PREP_DATA_PREFIX)){
    	if(!create_directory(PREP_DATA_PREFIX,S_IRWXU)){
    		throw file_error("could not mkdir " + PREP_DATA_PREFIX);
    	}
    }

    /*
    *	initialization networking part
    */
    server.resize(nthreads*nclients);
    int port_num = pnbase;
    for(int client_no = 0; client_no<nclients; client_no++){
        for(int i=0; i<nthreads; i++){
            server[client_no*nthreads + i] = new ServerSocket(port_num);
            server[client_no*nthreads + i]->init();
            port_num += sgx_mpsi::port_increase;
        }
    }

    socket_num.resize(nthreads*nclients);
    re_X=new size_t*[nclients];



    
    for(int client_no = 0; client_no<nclients; client_no++){
        for(int i=0; i<nthreads; i++){
            cout << "Waiting for client " << client_no << " thread " << i << endl;
            socket_num[client_no*nthreads + i] = server[client_no*nthreads + i]->get_connection_socket(client_no*nthreads + i);
            cout << "Connected to client " << client_no << " thread " << i << endl;

            send(socket_num[client_no*nthreads + i], GO); 

        }
        init(client_no,X[client_no],len[client_no]); 
    }
    
   
    // for multi-threads
    mutex_go = PTHREAD_MUTEX_INITIALIZER;
   
    
}



size_t decToBin(size_t dec){
    int result = 0, temp = dec, j = 1;
    while(temp){
        result = result + j * (temp % 2);
        temp = temp / 2;
        j = j * 10;
    }
    return result;
}

size_t binToDec(string final){
     size_t p=1;
     size_t s=0;
     for (int i = final.length()-1; i >= 0; i--) {
        size_t x = final[i] - '0'; 
        s += x * p;
        p *= 2; 
    }
    return s;
}

void pack(vector< uint8_t >& dst, size_t& data){
    uint8_t * src = static_cast < uint8_t* >(static_cast < void * >(&data));
    dst.insert (dst.end(), src, src + sizeof (size_t));
}

// void unpack(vector <uint8_t >& src, size_t index, size_t& data){
//     string final;
//     for(int i=src.size()-1;i>=0;i--)
//     {   
//         final.append(std::to_string(decToBin((size_t)src[i])));
//     }
//     data=binToDec(final);
// }


void unpack(uint8_t* src, size_t len, size_t& data){
    memcpy(&data, src, len);  
}


void server_core::attestation()
{
    system("echo do attestation!");
    //system("./run-server -v 7777");
//     config_t config;
//     sgx_launch_token_t token= { 0 };
//     sgx_status_t status;
//     sgx_enclave_id_t eid= 0;
//     int updated= 0;
//     int sgx_support;
//     uint32_t i;
//     EVP_PKEY *service_public_key= NULL;
//     char have_spid= 0;
//     char flag_stdio= 0;

//     /* Create a logfile to capture debug output and actual msg data */
//     fplog = create_logfile("client.log");
//     dividerWithText(fplog, "Client Log Timestamp");

//     const time_t timeT = time(NULL);
//     struct tm lt, *ltp;


//     ltp = localtime(&timeT);
//     if ( ltp == NULL ) {
//         perror("localtime");
//         return 1;
//     }
//     lt= *ltp;

//     fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n", 
//         lt.tm_year + 1900, 
//         lt.tm_mon + 1, 
//         lt.tm_mday,  
//         lt.tm_hour, 
//         lt.tm_min, 
//         lt.tm_sec);
//     divider(fplog);


//     memset(&config, 0, sizeof(config));
//     config.mode= MODE_ATTEST;

//     static struct option long_opt[] =
//     {
//         {"help",        no_argument,        0, 'h'},        
//         {"debug",       no_argument,        0, 'd'},
//         {"epid-gid",    no_argument,        0, 'e'},
//         {"pse-manifest",
//                         no_argument,        0, 'm'},
//         {"nonce",       required_argument,  0, 'n'},
//         {"nonce-file",  required_argument,  0, 'N'},
//         {"rand-nonce",  no_argument,        0, 'r'},
//         {"spid",        required_argument,  0, 's'},
//         {"spid-file",   required_argument,  0, 'S'},
//         {"linkable",    no_argument,        0, 'l'},
//         {"pubkey",      optional_argument,  0, 'p'},
//         {"pubkey-file", required_argument,  0, 'P'},
//         {"quote",       no_argument,        0, 'q'},
//         {"verbose",     no_argument,        0, 'v'},
//         {"stdio",       no_argument,        0, 'z'},
//         { 0, 0, 0, 0 }
//     };

//     /* Parse our options */

//     while (1) {
//         int c;
//         int opt_index= 0;
//         unsigned char keyin[64];

//         c= getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt,
//             &opt_index);
//         if ( c == -1 ) break;

//         switch(c) {
//         case 0:
//             break;
//         case 'N':
//             if ( ! from_hexstring_file((unsigned char *) &config.nonce,
//                     optarg, 16)) {

//                 fprintf(stderr, "nonce must be 32-byte hex string\n");
//                 exit(1);
//             }
//             SET_OPT(config.flags, OPT_NONCE);

//             break;
//         case 'P':
//             if ( ! key_load_file(&service_public_key, optarg, KEY_PUBLIC) ) {
//                 fprintf(stderr, "%s: ", optarg);
//                 crypto_perror("key_load_file");
//                 exit(1);
//             } 

//             if ( ! key_to_sgx_ec256(&config.pubkey, service_public_key) ) {
//                 fprintf(stderr, "%s: ", optarg);
//                 crypto_perror("key_to_sgx_ec256");
//                 exit(1);
//             }
//             SET_OPT(config.flags, OPT_PUBKEY);

//             break;
//         case 'S':
//             if ( ! from_hexstring_file((unsigned char *) &config.spid,
//                     optarg, 16)) {

//                 fprintf(stderr, "SPID must be 32-byte hex string\n");
//                 exit(1);
//             }
//             ++have_spid;

//             break;
//         case 'd':
//             debug= 1;
//             break;
//         case 'e':
//             config.mode= MODE_EPID;
//             break;
//         case 'l':
//             SET_OPT(config.flags, OPT_LINK);
//             break;
//         case 'm':
//             SET_OPT(config.flags, OPT_PSE);
//             break;
//         case 'n':
//             if ( strlen(optarg) < 32 ) {
//                 fprintf(stderr, "nonce must be 32-byte hex string\n");
//                 exit(1);
//             }
//             if ( ! from_hexstring((unsigned char *) &config.nonce,
//                     (unsigned char *) optarg, 16) ) {

//                 fprintf(stderr, "nonce must be 32-byte hex string\n");
//                 exit(1);
//             }

//             SET_OPT(config.flags, OPT_NONCE);

//             break;
//         case 'p':
//             if ( ! from_hexstring((unsigned char *) keyin,
//                     (unsigned char *) optarg, 64)) {

//                 fprintf(stderr, "key must be 128-byte hex string\n");
//                 exit(1);
//             }

//              Reverse the byte stream to make a little endien style value 
//             for(i= 0; i< 32; ++i) config.pubkey.gx[i]= keyin[31-i];
//             for(i= 0; i< 32; ++i) config.pubkey.gy[i]= keyin[63-i];

//             SET_OPT(config.flags, OPT_PUBKEY);

//             break;
//         case 'q':
//             config.mode = MODE_QUOTE;
//             break;
//         case 'r':
//             for(i= 0; i< 2; ++i) {
//                 int retry= 10;
//                 unsigned char ok= 0;
//                 uint64_t *np= (uint64_t *) &config.nonce;

//                 while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
//                 if ( ok == 0 ) {
//                     fprintf(stderr, "nonce: RDRAND underflow\n");
//                     exit(1);
//                 }
//             }
//             SET_OPT(config.flags, OPT_NONCE);
//             break;
//         case 's':
//             if ( strlen(optarg) < 32 ) {
//                 fprintf(stderr, "SPID must be 32-byte hex string\n");
//                 exit(1);
//             }
//             if ( ! from_hexstring((unsigned char *) &config.spid,
//                     (unsigned char *) optarg, 16) ) {

//                 fprintf(stderr, "SPID must be 32-byte hex string\n");
//                 exit(1);
//             }
//             ++have_spid;
//             break;
//         case 'v':
//             verbose= 1;
//             break;
//         case 'z':
//             flag_stdio= 1;
//             break;
//         case 'h':
//         case '?':
//         default:
//             usage();
//         }
//     }

//     argc-= optind;
//     if ( argc > 1 ) usage();

//     /* Remaining argument is host[:port] */

//     if ( flag_stdio && argc ) usage();
//     else if ( !flag_stdio && ! argc ) {
//         // Default to localhost
//         config.server= strdup("localhost");
//         if ( config.server == NULL ) {
//             perror("malloc");
//             return 1;
//         }
//     } else if ( argc ) {
//         char *cp;

//         config.server= strdup(argv[optind]);
//         if ( config.server == NULL ) {
//             perror("malloc");
//             return 1;
//         }
        
//         /* If there's a : then we have a port, too */
//         cp= strchr(config.server, ':');
//         if ( cp != NULL ) {
//             *cp++= '\0';
//             config.port= cp;
//         }
//     }

//     if ( ! have_spid && config.mode != MODE_EPID ) {
//         fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
//         return 1;
//     }

//     /* Can we run SGX? */

// #ifndef SGX_HW_SIM
//     sgx_support = get_sgx_support();
//     if (sgx_support & SGX_SUPPORT_NO) {
//         fprintf(stderr, "This system does not support Intel SGX.\n");
//         return 1;
//     } else {
//         if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
//             fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
//             return 1;
//         }
//         else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
//             fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
//             return 1;
//         }
//         else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
//             fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
//             fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
//             return 1;
//         }
//     } 
// #endif

//     /* Launch the enclave */
//     /*sgx_create_enclave_search() —————> sgx_create_enclave()*/
//     status = sgx_create_enclave_search(ENCLAVE_NAME,
//         SGX_DEBUG_FLAG, &token, &updated, &eid, 0);

//     printf("failed status is %d\n",status);
//     if ( status != SGX_SUCCESS ) {
//         fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
//             ENCLAVE_NAME, status);
//         if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
//             fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
//         return 1;
//     }


//     /* Are we attesting, or just spitting out a quote? */

//     //printf("[DEBUG]config.mode:%d\n",config.mode);
//     if ( config.mode == MODE_ATTEST ) {
//         do_attestation(eid, &config);
//     } else if ( config.mode == MODE_EPID || config.mode == MODE_QUOTE ) {
//         do_quote(eid, &config);
//     } else {
//         fprintf(stderr, "Unknown operation mode.\n");
//         return 1;
//     }

     
//     close_logfile(fplog);

//     return 0;
}



int get_file_content(string sFileName, string& sFileContent) 
{ 
  ifstream ifs (sFileName.c_str(), ifstream::in); 
  
  sFileContent.clear(); 
  char c; 
    while (ifs.get(c)){ 
    sFileContent.append(1, c); 
  } 
  
  ifs.close(); 
  
  return 0; 
} 


// 私钥解密    
string rsa_pri_decrypt(const string &cipherText, const string &priKey)  
{  
    std::string strRet;  
    RSA *rsa = RSA_new();  
    BIO *keybio;  
    keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);  
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);  
  
    int len = RSA_size(rsa);  
    char *decryptedText = (char *)malloc(len + 1);  
    memset(decryptedText, 0, len + 1);  
  
    // 解密函数  
    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);  
    if (ret >= 0)  
        strRet = std::string(decryptedText, ret);  
  
    // 释放内存  
    free(decryptedText);  
    BIO_free_all(keybio);  
    RSA_free(rsa);  
  
    return strRet;  
}

static unsigned char key[AES_BLOCK_SIZE*2] = "1wradfr4e3fefefad4545454h6thrsf";
int aes256_decrypt(char* str_in, char* out)
{
     int i;
     int len;
     AES_KEY aes;
     unsigned char iv[AES_BLOCK_SIZE] = {0};
     
      if (!str_in || !out)
          return -1;
      
      len = strlen(str_in);
      for (i = 0; i < 16; ++i)  
         iv[i] = i+32;

      if (AES_set_decrypt_key((unsigned char*)key, 256, &aes) < 0)
      {
         return -1;
      }
     
     AES_cbc_encrypt((unsigned char*)str_in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
     return 0;  
  }


string des_decrypt(const string &cipherText, const string &key)
{
    string clearText; // 明文  
 
    DES_cblock keyEncrypt;
    memset(keyEncrypt, 0, 8);
 
    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);
 
    DES_key_schedule keySchedule;
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);
 
    const_DES_cblock inputText;
    DES_cblock outputText;
    std::vector<unsigned char> vecCleartext;
    unsigned char tmp[8];
 
    for (int i = 0; i < cipherText.length() / 8; i++)
    {
        memcpy(inputText, cipherText.c_str() + i * 8, 8);
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
        memcpy(tmp, outputText, 8);
 
        for (int j = 0; j < 8; j++)
            vecCleartext.push_back(tmp[j]);
    }
 
    if (cipherText.length() % 8 != 0)
    {
        int tmp1 = cipherText.length() / 8 * 8;
        int tmp2 = cipherText.length() - tmp1;
        memset(inputText, 0, 8);
        memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
        // 解密函数  
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
        memcpy(tmp, outputText, 8);
 
        for (int j = 0; j < 8; j++)
            vecCleartext.push_back(tmp[j]);
    }
 
    clearText.clear();
    clearText.assign(vecCleartext.begin(), vecCleartext.end());
 
    return clearText;
}




void server_core::init(int client_no,size_t *X_i,size_t len_i)
{
    cout<<"server is doing init now including (sending data to the client)"<<endl;

    std::vector<uint8_t> buff_1;
    pack(buff_1,len_i);
    uint8_t *test_1=new uint8_t[buff_1.size()];
    for(int i=0;i<buff_1.size();i++)   
        test_1[i]=buff_1[i];
    send_to(client_no*nthreads, test_1 ,buff_1.size());
    
    for(int n=0;n<len_i;n++)
    { 
        //cout<<"X_send["<<n<<"]:"<<X_i[n]<<endl;
        std::vector<uint8_t> buff;
        pack(buff,X_i[n]);
        uint8_t *test=new uint8_t[buff.size()];
        for(int i=0;i<buff.size();i++) 
            test[i]=buff[i];
        send_to(client_no*nthreads, test ,buff.size());
    }
    cout<<"send data end"<<endl;

    for(int i=0;i<nclients;i++)
        re_X[i]=new size_t[len_i];

    cout<<"init all finished!"<<endl;
    start(client_no);
}


void server_core::start(int client_no){

    // cout<<"server side sucessfully start\n";//准备接收client发送的数据（进行运算）

    // int inst=-1;
    // while (inst != ATT) 
    // { 
    //     receive(socket_num[client_no*nthreads], inst); 
    // }

    // for(int i=0;i<len_i;i++)
    // {
    //     uint8_t *inst_2=new uint8_t[200000];
    //     size_t len_2;
    //     receive_from(client_no*nthreads, inst_2,len_2); 
    //     unpack(inst_2,len_2,re_X[client_no][i]);
    //     //cout<<"re_X["<<client_no<<"]["<<i<<"]:"<<re_X[client_no][i]<<endl;
    // }
    // cout<<"i have received the data  client"<<client_no<<" send"<<endl;
    cout<<"server"<<endl;
    /*getpk()*/
    int inst=-1;
    while (inst != getpk) 
    { 
        receive(socket_num[client_no*nthreads], inst); 
    }
    cout<<"1-server receive the signal 'getpk' "<<endl;

    string rsa_public_key; 
    get_file_content("Server_Storage/fake_rsa_public.pem", rsa_public_key); 
    //cout << rsa_public_key << endl; 
    string rsa_private_key; 
    get_file_content("Server_Storage/fake_rsa_private.pem", rsa_private_key); 
    //cout << rsa_private_key << endl; 

    send_to(client_no*nthreads,(uint8_t *)rsa_public_key.data(),rsa_public_key.size());
    //cout<<rsa_public_key.size()<<endl;

    /*pk(ki)*/
    send(socket_num[client_no*nthreads], exKey); 
    cout<<"2-server send the signal 'exKey' "<<endl;
    uint8_t *data=new uint8_t[2000];
    size_t len;
    receive_from(client_no*nthreads, data,len);
    //cout<<len<<endl; 

    string pkki(data,data+len);
    string key=rsa_pri_decrypt(pkki,rsa_private_key);
    cout<<"2-server receive the ki:"<<key<<endl;

    /*ki(mi)*/
    send(socket_num[client_no*nthreads], setsize); 
    cout<<"3-server send the signal 'setszie' "<<endl;
    size_t len_i=0;
    uint8_t *inst_1=new uint8_t[200];
    size_t len_1;
    receive_from(client_no*nthreads, inst_1,len_1); 

    string mlen(inst_1,inst_1+len_1);
    int position;
    position = mlen.find("+");
    string mlen_front;
    string mlen_back;
    if (position != mlen.npos)  //如果没找到，返回一个特别的标志c++中用npos表示，我这里npos取值是4294967295，
    {
        mlen_back=mlen.substr(position+1);
        mlen_front=mlen.substr(0,position);
    }
    
    string messagelen=des_decrypt(mlen_front,key);
    cout<<"3-server receive the mi:"<<messagelen<<endl;
    // unpack(inst_1, len_1, len_i);
    // char length_m[200];
    // char length_c[200];
    // int aes=aes256_decrypt(length_c,length_m);
    // cout<<aes<<endl;
    // cout<<"len_i:"<<atoi(length_m)<<endl;
    
}


bool equal(uint8_t* a, uint8_t* b, const size_t& len){
    bool ret = true;
    for(size_t i=0; i<len; i++){
        ret &= (a[i] == b[i]);
    }
    return ret;
}

server_core::~server_core(){
	for(int i=0; i<nthreads; i++){
        delete server[i];
        close(socket_num[i]);
    }
}


void server_core::receive_from(int thread_num, uint8_t* data, size_t& data_len) const{
    receive(socket_num[thread_num], data_len,LENGTH_SIZE);
    receive(socket_num[thread_num], data, data_len);
}

void server_core::send_to(int thread_num, uint8_t* data, size_t data_len) const{
    send(socket_num[thread_num], data_len, LENGTH_SIZE);
    send(socket_num[thread_num], data, data_len);
}
