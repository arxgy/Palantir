#ifndef _EAPP_PRIVIL_OCALL
#define _EAPP_PRIVIL_OCALL

#define PAGE_SIZE 1 << 12

#define NAME_LEN        16
#define ELF_FILE_LEN    256

#define RETURN_USER_EXIT_ENCL             0
#define RETURN_USER_RELAY_PAGE            1
#define RETURN_USER_NE_IRQ                2
#define RETURN_USER_NE_REQUEST            3

#define NE_REQUEST_INSPECT                10
#define NE_REQUEST_SHARE_PAGE             11
/* todo: host-level update */
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

/* used in RUN & RESUME */
typedef struct ocall_run_param
{
  int run_eid;
  int resume_reason;  // let sdk read (RDONLY), sync with *reason_ptr.
  unsigned long reason_ptr;
  unsigned long retval_ptr;
  unsigned long request_reason;  // NE_REQUEST_INSPECT, NE_REQUEST_SHARE_PAGE, ...
  unsigned long request_arg;     // VA in PE
} ocall_run_param_t;

typedef struct ocall_inspect_param
{
  int inspect_eid;
  unsigned long inspect_address; // VA in NE
  unsigned long inspect_size;
  int reason;  // let sdk read (RDONLY), sync with *reason_ptr.
  unsigned long reason_ptr;
  unsigned long inspect_result; // VA in PE
} ocall_inspect_param_t;


typedef struct ocall_request
{
  unsigned long request;            // reason in PE
  unsigned long inspect_request;    // VA in NE
  unsigned long share_page_request; // VA in NE
  /* todo. support more requests */
} ocall_request_t;

typedef struct ocall_request_inspect
{
    unsigned long inspect_ptr;
    unsigned long inspect_size;
} ocall_request_inspect_t;


#endif