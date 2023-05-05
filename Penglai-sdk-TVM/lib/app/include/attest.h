#ifndef _ENCLAVE_ATTEST_H
#define _ENCLAVE_ATTEST_H

#define PRIVATE_KEY_SIZE       32
#define PUBLIC_KEY_SIZE        64
#define HASH_SIZE              32
#define SIGNATURE_SIZE         64

struct sm_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  unsigned char sm_pub_key[PUBLIC_KEY_SIZE];
};

struct enclave_report_t
{
  unsigned char hash[HASH_SIZE];
  unsigned char signature[SIGNATURE_SIZE];
  unsigned long nonce;
};

struct report_t
{
  struct sm_report_t sm;
  struct enclave_report_t enclave;
  unsigned char dev_pub_key[PUBLIC_KEY_SIZE];
};

enum key_type_t {
    ENCLAVE_KEY = 0,
    STORAGE_KEY,
    ATTEST_KEY
};
#endif