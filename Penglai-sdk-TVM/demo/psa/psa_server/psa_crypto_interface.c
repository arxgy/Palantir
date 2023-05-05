#include "psa_crypto_interface.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "eapp.h"
#include "print.h"
#include "attest.h"
#include <string.h>
#include <stdlib.h>
#include "psa/crypto_types.h"
#include "psa/crypto.h"

#include "mbedtls/platform_util.h" // for mbedtls_platform_zeroize

/* Run a PSA function and bail out if it fails. */
#define PSA_CHECK( expr )                                       \
    do                                                          \
    {                                                           \
        status = ( expr );                                      \
        if( status != PSA_SUCCESS )                             \
        {                                                       \
            eapp_print( "Error %d at line %d: %s\n",                \
                    (int) status,                               \
                    __LINE__,                                   \
                    #expr );                                    \
            goto exit;                                          \
        }                                                       \
    }                                                           \
    while( 0 )

/* Size of the key derivation keys (applies both to the master key and
 * to intermediate keys). */
#define KEY_SIZE_BYTES 32

/* Algorithm for key derivation. */
#define KDF_ALG PSA_ALG_HKDF( PSA_ALG_SHA_256 )

/* Type and size of the key used to wrap data. */
#define WRAPPING_KEY_TYPE PSA_KEY_TYPE_AES
#define WRAPPING_KEY_BITS 128

/* Cipher mode used to wrap data. */
#define WRAPPING_ALG PSA_ALG_CCM

/* Nonce size used to wrap data. */
#define WRAPPING_IV_SIZE 13

/* Salt to use when deriving an intermediate key. */
#define DERIVE_KEY_SALT ( (uint8_t *) "psa_server_demo.derive" )
#define DERIVE_KEY_SALT_LENGTH ( strlen( (const char*) DERIVE_KEY_SALT ) )

/* Salt to use when deriving a wrapping key. */
#define WRAPPING_KEY_SALT ( (uint8_t *) "psa_server_demo.wrap" )
#define WRAPPING_KEY_SALT_LENGTH ( strlen( (const char*) WRAPPING_KEY_SALT ) )

/* Derive the intermediate keys, using the list of labels provided on
 * the command line. On input, *key is the master key identifier.
 * This function destroys the master key. On successful output, *key
 * is the identifier of the final derived key.
 */
static psa_status_t derive_key_ladder( char *salt,
                                       size_t salt_len,
                                       psa_key_id_t *key )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;
    size_t i;

    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT );
    psa_set_key_algorithm( &attributes, KDF_ALG );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_DERIVE );
    psa_set_key_bits( &attributes, PSA_BYTES_TO_BITS( KEY_SIZE_BYTES ) );

    /* For each label in turn, ... */

    /* Start deriving material from the master key (if i=0) or from
        * the current intermediate key (if i>0). */
    PSA_CHECK( psa_key_derivation_setup( &operation, KDF_ALG ) );
    PSA_CHECK( psa_key_derivation_input_bytes(
                    &operation, PSA_KEY_DERIVATION_INPUT_SALT,
                    DERIVE_KEY_SALT, DERIVE_KEY_SALT_LENGTH ) );
    PSA_CHECK( psa_key_derivation_input_key(
                    &operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                    *key ) );
    PSA_CHECK( psa_key_derivation_input_bytes(
                    &operation, PSA_KEY_DERIVATION_INPUT_INFO,
                    (uint8_t*) salt, salt_len) );
    /* When the parent key is not the master key, destroy it,
        * since it is no longer needed. */
    PSA_CHECK( psa_destroy_key( *key ) );
    *key = 0;
    /* Derive the next intermediate key from the parent key. */
    PSA_CHECK( psa_key_derivation_output_key( &attributes, &operation,
                                                key ) );
    PSA_CHECK( psa_key_derivation_abort( &operation ) );


exit:
    psa_key_derivation_abort( &operation );
    if( status != PSA_SUCCESS )
    {
        psa_destroy_key( *key );
        *key = 0;
    }
    return( status );
}


/* Load the master key from a file.
 *
 * In the real world, this master key would be stored in an internal memory
 * and the storage would be managed by the keystore capability of the PSA
 * crypto library. */
static psa_status_t import_key_from_file( psa_key_usage_t usage,
                                          psa_algorithm_t alg,
                                          psa_key_id_t *master_key )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t key_data[KEY_SIZE_BYTES];
    PSA_CHECK(get_key(STORAGE_KEY, key_data, KEY_SIZE_BYTES));

    size_t key_size = KEY_SIZE_BYTES;

    psa_set_key_usage_flags( &attributes, usage );
    psa_set_key_algorithm( &attributes, alg );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_DERIVE );
    PSA_CHECK( psa_import_key( &attributes, key_data, key_size, master_key ) );
exit:
    mbedtls_platform_zeroize( key_data, sizeof( key_data ) );
    if( status != PSA_SUCCESS )
    {
        /* If the key creation hasn't happened yet or has failed,
         * *master_key is null. psa_destroy_key( 0 ) is
         * guaranteed to do nothing and return PSA_SUCCESS. */
        (void) psa_destroy_key( *master_key );
        *master_key = 0;
    }
    return( status );
}

/* Derive a wrapping key from the last intermediate key. */
static psa_status_t derive_wrapping_key( psa_key_usage_t usage,
                                         psa_key_id_t derived_key,
                                         psa_key_id_t *wrapping_key )
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    *wrapping_key = 0;

    /* Set up a key derivation operation from the key derived from
     * the master key. */
    PSA_CHECK( psa_key_derivation_setup( &operation, KDF_ALG ) );
    PSA_CHECK( psa_key_derivation_input_bytes(
                   &operation, PSA_KEY_DERIVATION_INPUT_SALT,
                   WRAPPING_KEY_SALT, WRAPPING_KEY_SALT_LENGTH ) );
    PSA_CHECK( psa_key_derivation_input_key(
                   &operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                   derived_key ) );
    PSA_CHECK( psa_key_derivation_input_bytes(
                   &operation, PSA_KEY_DERIVATION_INPUT_INFO,
                   NULL, 0 ) );

    /* Create the wrapping key. */
    psa_set_key_usage_flags( &attributes, usage );
    psa_set_key_algorithm( &attributes, WRAPPING_ALG );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_AES );
    psa_set_key_bits( &attributes, WRAPPING_KEY_BITS );
    PSA_CHECK( psa_key_derivation_output_key( &attributes, &operation,
                                              wrapping_key ) );

exit:
    psa_key_derivation_abort( &operation );
    return( status );
}

/* FIXME: add the tag length to the crypto buffer size to account for the tag
 * being appended to the ciphertext by the crypto layer.
 */
static uint8_t sst_crypto_iv_buf[SST_IV_LEN_BYTES];

void sst_crypto_get_iv(union sst_crypto_t *crypto)
{
    uint64_t iv_l;
    uint32_t iv_h;

    (void)memcpy(&iv_l, sst_crypto_iv_buf, sizeof(iv_l));
    (void)memcpy(&iv_h, (sst_crypto_iv_buf+sizeof(iv_l)), sizeof(iv_h));
    iv_l++;
    /* If overflow, increment the MSBs */
    if (iv_l == 0) {
        iv_h++;
    }

    /* Update the local buffer */
    (void)memcpy(sst_crypto_iv_buf, &iv_l, sizeof(iv_l));
    (void)memcpy((sst_crypto_iv_buf + sizeof(iv_l)), &iv_h, sizeof(iv_h));
    /* Update the caller buffer */
    (void)memcpy(crypto->ref.iv, sst_crypto_iv_buf, SST_IV_LEN_BYTES);
}

void sst_crypto_set_iv(const union sst_crypto_t *crypto)
{
    (void)memcpy(sst_crypto_iv_buf, crypto->ref.iv, SST_IV_LEN_BYTES);
}

psa_status_t sst_crypto_auth_and_decrypt(const union sst_crypto_t *crypto,
                                         const uint8_t *add,
                                         size_t add_len,
                                         uint8_t *in,
                                         size_t in_len,
                                         uint8_t *out,
                                         size_t out_size,
                                         size_t *out_len,
                                         uint8_t *salt,
                                         size_t salt_len)
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t derivation_key = 0;
    psa_key_id_t wrapping_key = 0;

    PSA_CHECK( psa_crypto_init( ) );
    PSA_CHECK( import_key_from_file( PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                                     KDF_ALG,
                                     &derivation_key ) );
    PSA_CHECK( derive_key_ladder( salt, salt_len,
                                  &derivation_key ) );

    PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_DECRYPT,
                                            derivation_key,
                                            &wrapping_key ) );
     /* Copy the tag into the input buffer */
    (void)memcpy((in + in_len), crypto->ref.tag, SST_TAG_LEN_BYTES);
    in_len += SST_TAG_LEN_BYTES;

    /* Unwrap the data. */
    PSA_CHECK( psa_aead_decrypt( wrapping_key, WRAPPING_ALG,
                                 crypto->ref.iv, SST_IV_LEN_BYTES,
                                 add, add_len,
                                 in, in_len,
                                 out, out_size, out_len));

    if (status != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    (void) psa_destroy_key( derivation_key );
    (void) psa_destroy_key( wrapping_key );
    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free( );

    return PSA_SUCCESS;
}

psa_status_t sst_crypto_encrypt_and_tag(union sst_crypto_t *crypto,
                                        const uint8_t *add,
                                        size_t add_len,
                                        const uint8_t *in,
                                        size_t in_len,
                                        uint8_t *out,
                                        size_t out_size,
                                        size_t *out_len,
                                        uint8_t *salt,
                                        size_t salt_len)
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t derivation_key = 0;
    psa_key_id_t wrapping_key = 0;

    PSA_CHECK( psa_crypto_init( ) );
    PSA_CHECK( import_key_from_file( PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                                     KDF_ALG,
                                     &derivation_key ) );
    PSA_CHECK( derive_key_ladder( salt, salt_len,
                                  &derivation_key ) );

    PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_ENCRYPT,
                                            derivation_key,
                                            &wrapping_key ) );

    /* Unwrap the data. */
    PSA_CHECK( psa_aead_encrypt( wrapping_key, WRAPPING_ALG,
                                 crypto->ref.iv, SST_IV_LEN_BYTES,
                                 add, add_len,
                                 in, in_len,
                                 out, out_size, out_len));
  
    if (status != PSA_SUCCESS) {
        eapp_print("sst_crypto_encrypt_and_tag: psa_aesgcm_encrypt is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    *out_len -= SST_TAG_LEN_BYTES;
    (void)memcpy(crypto->ref.tag, (out + *out_len), SST_TAG_LEN_BYTES);

exit:
    (void) psa_destroy_key( derivation_key );
    (void) psa_destroy_key( wrapping_key );
    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free( );
    return PSA_SUCCESS;
}

psa_status_t sst_crypto_generate_auth_tag(union sst_crypto_t *crypto,
                                          const uint8_t *add,
                                          uint32_t add_len,
                                          uint8_t *salt,
                                          size_t salt_len)
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t derivation_key = 0;
    psa_key_id_t wrapping_key = 0;
    size_t out_len;

    PSA_CHECK( psa_crypto_init( ) );
    PSA_CHECK( import_key_from_file( PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                                     KDF_ALG,
                                     &derivation_key ) );
    PSA_CHECK( derive_key_ladder( salt, salt_len,
                                  &derivation_key ) );

    PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_ENCRYPT,
                                            derivation_key,
                                            &wrapping_key ) );

    /* Unwrap the data. */
    PSA_CHECK( psa_aead_encrypt( wrapping_key, WRAPPING_ALG,
                                 crypto->ref.iv, SST_IV_LEN_BYTES,
                                 add, add_len,
                                 0, 0,
                                 crypto->ref.tag, SST_TAG_LEN_BYTES, &out_len));
    
    if (status != PSA_SUCCESS) {
        eapp_print("sst_crypto_generate_auth_tag: psa_aesgcm_encrypt is failed \n");
        return PSA_ERROR_GENERIC_ERROR;
    }

exit:
    (void) psa_destroy_key( derivation_key );
    (void) psa_destroy_key( wrapping_key );
    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free( );

    return PSA_SUCCESS;
}

psa_status_t sst_crypto_authenticate(const union sst_crypto_t *crypto,
                                     const uint8_t *add,
                                     uint32_t add_len,
                                     uint8_t *salt,
                                     size_t salt_len)
{
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t derivation_key = 0;
    psa_key_id_t wrapping_key = 0;
    size_t out_len;

    PSA_CHECK( psa_crypto_init( ) );
    PSA_CHECK( import_key_from_file( PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT,
                                     KDF_ALG,
                                     &derivation_key ) );
    PSA_CHECK( derive_key_ladder( salt, salt_len,
                                  &derivation_key ) );

    PSA_CHECK( derive_wrapping_key( PSA_KEY_USAGE_DECRYPT,
                                            derivation_key,
                                            &wrapping_key ) );

    /* Unwrap the data. */
    PSA_CHECK( psa_aead_decrypt( wrapping_key, WRAPPING_ALG,
                                 crypto->ref.iv, SST_IV_LEN_BYTES,
                                 add, add_len,
                                 crypto->ref.tag, SST_TAG_LEN_BYTES,
                                 0, 0, &out_len));
    if (status != PSA_SUCCESS) {
        eapp_print("sst_crypto_authenticate: psa_aesgcm_decrypt is failed \n");
        return PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    (void) psa_destroy_key( derivation_key );
    (void) psa_destroy_key( wrapping_key );
    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free( );

    return PSA_SUCCESS;
}