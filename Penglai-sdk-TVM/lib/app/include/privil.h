#ifndef _EAPP_PRIVIL_OCALL
#define _EAPP_PRIVIL_OCALL

#define NAME_LEN        16
#define ELF_FILE_LEN    256

// #define PRIVATE_KEY_SIZE       32
// #define PUBLIC_KEY_SIZE        64
// #define HASH_SIZE              32
// #define SIGNATURE_SIZE         64

// struct sm_report_t
// {
//   unsigned char hash[HASH_SIZE];
//   unsigned char signature[SIGNATURE_SIZE];
//   unsigned char sm_pub_key[PUBLIC_KEY_SIZE];
// };
// struct enclave_report_t
// {
//   unsigned char hash[HASH_SIZE];
//   unsigned char signature[SIGNATURE_SIZE];
//   uintptr_t nonce;
// };

// struct report_t
// {
//   struct sm_report_t sm;
//   struct enclave_report_t enclave;
//   unsigned char dev_pub_key[PUBLIC_KEY_SIZE];
// };

/* todo: host-level update */
/* maybe conflict */
typedef enum
{
  NORMAL_ENCLAVE = 0,
  SERVER_ENCLAVE = 1,
  SHADOW_ENCLAVE = 2, 
  PRIVIL_ENCLAVE = 3
} enclave_type_t;
/* app-level PE create enclave param */
typedef struct ocall_create_param
{
  /* enclave */
  unsigned int eid;
  
  /* enclaveFile */
  unsigned long elf_file_size;
  unsigned long elf_file_ptr; // VA from enclave
  /* params */
  char encl_name [NAME_LEN];
  enclave_type_t encl_type;
  unsigned long stack_size;
  int shmid;
  unsigned long shm_offset;
  unsigned long shm_size;
  char elf_file_name [ELF_FILE_LEN];


} ocall_create_param_t;


typedef struct ocall_attest_param
{
  int attest_eid;
  int current_eid;
  int isShadow;
  unsigned long nonce;
  unsigned long report_ptr; // VA
} ocall_attest_param_t;

#endif