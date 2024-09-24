/**
 * This program is a Privileged Enclave demo in Hierarchical Deterministic Wallet case study,
 * which is supported to do nested account distribution and key derivation
 * 
 *  by Anonymous Author @ Sep 22, 2024.
*/
#include "eapp.h"
#include "print.h"
#include "privil.h"
#include "bip32_bip39.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ENTRY_POINT 0x1000

#define DEFAULT_STACK_SIZE  64*1024
#define CE_NUMBER 1

typedef struct share_record
{
  int eid;  // idr-layer, owner of the page.
  int share_id;
  unsigned long vaddr;
  unsigned long size;
} share_record_t;

int thread_valid[CE_NUMBER];

/* A trivial round-robin scheduler. */
int ne_scheduler(int prev)
{
  int i = (prev+1)%CE_NUMBER;
  while (i != prev)
  {
    if (thread_valid[i])
      break;
    i = (i+1)%CE_NUMBER;
  }
  return i;
}

int share_id_alloc(int *prev)
{
  return ++(*prev);
}

void __printHexData__(char * loghea,unsigned char  *pData, int nLen) {
	unsigned char *msg =  malloc(nLen * 2 + 1);
	memset(msg, 0, nLen * 2 + 1);
	HexToStr((char *)msg, pData, nLen);
	eapp_print("%s = %s ,len = %d \n",loghea,msg,nLen * 2);
	free(msg);
}

void print_HDNode(HDNode *node){
  eapp_print("[print_HDNode] depth = %d\n",node->depth);
  eapp_print("[print_HDNode] child_num = %d\n",node->child_num);
  __printHexData__("[print_HDNode] chain_code",node->chain_code,32);
  __printHexData__("[print_HDNode] private_key",node->private_key,32);
  __printHexData__("[print_HDNode] public_key",node->public_key,33);
}

unsigned long get_cycle(void){
	unsigned long n;
	 __asm__ __volatile__("rdcycle %0" : "=r"(n));
	 return n;
}

int execute(unsigned long * args)
{ 
  eapp_print("setup root enclave end (& setup mid begin): %lx\n", get_cycle());
  int retval = 0, prev = 0;
  int requested = 0, i = 0, thread_init = 0;
  /* CREATE CEs begin */
  char *elf_file_names[CE_NUMBER] = {"/root/case-wallet-mid"};
  int share_id_counts[CE_NUMBER];
  memset(share_id_counts, 0, sizeof(int)*CE_NUMBER);
  // share_record_t share_records[SHARE_LIMIT];
  // memset(share_records, 0, SHARE_LIMIT*sizeof(share_record_t));
  int share_record_count = 0;

  ocall_create_param_t create_params[CE_NUMBER];
  for (i = 0 ; i < CE_NUMBER ; i++)
  { 
    create_params[i].elf_file_ptr = (unsigned long)(&(create_params[i]));
    create_params[i].encl_type = PRIVIL_ENCLAVE;
    create_params[i].stack_size = DEFAULT_STACK_SIZE;
    create_params[i].migrate_arg = 0;
    /* disable shm currently */
    create_params[i].shmid = 0;
    create_params[i].shm_offset = 0;
    create_params[i].shm_size = 0;
    memcpy(create_params[i].elf_file_name, elf_file_names[i], ELF_FILE_LEN);
    retval = eapp_create_enclave((unsigned long)(&(create_params[i])));
    if (retval)
    {
      eapp_print("eapp_create_enclave failed: %d\n",retval);
    }
    // eapp_print("Allocated [%d]-th NORMAL ENCLAVE eid: [%d]\n", i, create_params[i].eid);
    share_id_counts[i] = 0;
  }
  /* CREATE CEs end */
  int return_reasons[CE_NUMBER], return_values[CE_NUMBER];
  ocall_run_param_t run_params[CE_NUMBER];
  ocall_request_t request_params[CE_NUMBER];
  ocall_response_t response_params[CE_NUMBER];
  ocall_request_share_t share_params[CE_NUMBER];
  ocall_response_share_t share_responses[CE_NUMBER];

  char *wallet_content = (char *)eapp_mmap(NULL, PAGE_SIZE);
  memset(wallet_content, 0, PAGE_SIZE);

  for (i = 0; i < CE_NUMBER ; i++)
  {
    thread_valid[i] = 1;
    run_params[i].run_eid = create_params[i].eid;
    run_params[i].reason_ptr = (unsigned long)(&(return_reasons[i]));
    run_params[i].retval_ptr = (unsigned long)(&(return_values[i]));
    run_params[i].request_arg = (unsigned long)(&(request_params[i]));
    run_params[i].response_arg = (unsigned long)(&(response_params[i]));

    request_params[i].share_page_request = (unsigned long)(&(share_params[i]));
    response_params[i].inspect_response = NULL;
    response_params[i].share_page_response = (unsigned long)(&(share_responses[i]));
  }

  unsigned long begin_cycle, end_cycle;
  begin_cycle = get_cycle();
  /* Root Key Generation */
  const char *passphrase ="";
  int keylength = 64;
  int COIN_TYPE = 0;
  char rootkey[112];
  uint32_t fingerprint = 0;
  HDNode rootnode;

  const char *mnemonic = "vault salon bonus asset raw rapid split balance logic employ fuel atom";
  uint8_t bip39_seed[keylength];

  unsigned long t_stamp = 0, t_seed = 0;
  for (int idx = 0 ; idx < REPEAT_TIME ; idx++)
  {
    t_stamp = get_cycle();
    generateBip39Seeed(mnemonic,bip39_seed,passphrase);
    hdnode_from_seed(bip39_seed,64, SECP256K1_NAME, &rootnode);
    hdnode_fill_public_key(&rootnode);
    t_seed += get_cycle() - t_stamp;
  }
  eapp_print("Master Key Generation time: %lx cycle\n", t_seed);


  int init_run[CE_NUMBER];
  memset(init_run, 0, CE_NUMBER*sizeof(int));

  i = 0;
  while (retval == 0)
  {
    thread_init = 0;
    requested = 0;
    if (!init_run[i])
    {
      retval = eapp_run_enclave((unsigned long)(&(run_params[i])));
      thread_init = 1;
      init_run[i] = 1;
      if (retval)
      {
        eapp_print("[pe] eapp_run_enclave non-zero [%d]\n", retval);
        break;
      }
    }
    prev = i;

    if (return_reasons[prev] == RETURN_USER_EXIT_ENCL)
    {
      eapp_print("[pe] thread: %d exit!\n", prev);
      thread_valid[prev] = 0;
      i = ne_scheduler(prev);
      
      if (i == prev)
        break;
    }
    response_params[prev].request = 0;

    switch (return_reasons[prev])
    {
      case NE_REQUEST_INSPECT:
        break;
      case NE_REQUEST_SHARE_PAGE:
        break;
      case NE_REQUEST_ACQUIRE_PAGE:
        requested = 1;

        /* Generate HD Account for CEs */
        HDNode childnode;
        memcpy(&childnode, &rootnode, sizeof(HDNode));
        hdnode_private_ckd(&childnode, prev);
        memcpy(wallet_content, &childnode, sizeof(HDNode));
        
        response_params[prev].request = NE_REQUEST_ACQUIRE_PAGE;
        share_responses[prev].src_ptr = (unsigned long)(wallet_content);
        share_responses[prev].dest_ptr = share_params[prev].share_content_ptr;
        share_responses[prev].share_size = share_params[prev].share_size;
        break;
      default:
        break;
    }
    // save previous NE pause reason.
    run_params[prev].resume_reason = return_reasons[prev];
    if (requested)
    {
      run_params[prev].resume_reason = RETURN_USER_NE_REQUEST;
    }

    // select next running enclave.
    i = ne_scheduler(prev);
    
    if (thread_init)
      continue;
    retval = eapp_resume_enclave((unsigned long)(&(run_params[i])));
  }
  end_cycle = get_cycle();
  eapp_print("pe: total_cycle [%lx]\n", end_cycle-begin_cycle);
  EAPP_RETURN(0);
}

int EAPP_ENTRY main(){
  unsigned long * args;
  EAPP_RESERVE_REG;
  execute(args);
}
